using System.Collections.Immutable;
using System.Text;

namespace billpg.WWWAuthenticateTools;

/// <summary>
/// Parses raw WWW-Authenticate-family header values into an
/// <see cref="AuthHeaders"/> model.
/// </summary>
/// <remarks>
/// WWW-Authenticate is one of the header fields RFC 9110/7230 says cannot
/// always be safely combined into one line by comma-joining multiple header
/// field instances, so the entry point takes one raw value string per
/// actual header line received, not a single pre-joined string.
/// </remarks>
public static class ParseHeader
{
    /// <summary>
    /// Parses one or more raw header line values into an <see cref="AuthHeaders"/>.
    /// </summary>
    /// <param name="headerLines">One entry per actual header line as received.</param>
    /// <param name="strict">
    /// When true, only RFC-conformant input is accepted. When false (default),
    /// a documented set of spec-violating-but-real-world inputs is also
    /// accepted. Lenient deviations are not yet implemented in this slice, so
    /// both modes currently behave identically (strict grammar only).
    /// </param>
    public static AuthHeaders Parse(IEnumerable<string> headerLines, bool strict = false)
    {
        if (headerLines is null)
            throw new ArgumentNullException(nameof(headerLines));

        var challenges = ImmutableArray.CreateBuilder<Challenge>();
        int lineIndex = 0;
        foreach (var line in headerLines)
        {
            ParseLine(line ?? string.Empty, lineIndex, challenges);
            lineIndex++;
        }
        return new AuthHeaders(challenges.ToImmutable());
    }

    private static void ParseLine(string line, int lineIndex, ImmutableArray<Challenge>.Builder output)
    {
        Challenge? current = null;
        foreach (var (segmentStart, segmentLength) in SplitTopLevelCommaSegments(line, lineIndex))
        {
            int trimmedStart = segmentStart;
            int trimmedEnd = segmentStart + segmentLength;
            while (trimmedStart < trimmedEnd && IsOws(line[trimmedStart]))
                trimmedStart++;
            while (trimmedEnd > trimmedStart && IsOws(line[trimmedEnd - 1]))
                trimmedEnd--;

            if (trimmedStart == trimmedEnd)
                throw Err(AuthHeaderErrorCodes.UnexpectedComma, "Empty element between commas.", lineIndex, segmentStart);

            string segment = line.Substring(trimmedStart, trimmedEnd - trimmedStart);
            int basePosition = trimmedStart;

            /* Two-token lookahead: a segment continues the current challenge only when
             * its first token is itself genuinely name=value shaped. If there's no open
             * challenge, the segment can only be a new challenge's head, regardless of
             * whether it happens to contain an '=' further in (e.g. a token68's own
             * "Digest realm=..." vs "Bearer abc123=="). */
            if (current is not null && SegmentContinuesChallenge(segment, out int eq))
            {
                var (name, value) = ParseNameValue(segment, eq, lineIndex, basePosition);
                if (current.HasParamNamed(name))
                    throw Err(AuthHeaderErrorCodes.DuplicateParam,
                        $"Duplicate param '{name}' on scheme '{current.Scheme}'.", lineIndex, basePosition);
                current = current.WithParamCore(name, value);
                continue;
            }

            if (current is not null)
                output.Add(current);

            current = ParseChallengeHead(segment, lineIndex, basePosition);
        }

        if (current is not null)
            output.Add(current);
    }

    private static Challenge ParseChallengeHead(string segment, int lineIndex, int basePosition)
    {
        int spaceIndex = IndexOfOws(segment);
        string schemeWord = spaceIndex < 0 ? segment : segment.Substring(0, spaceIndex);
        string remainder = spaceIndex < 0 ? string.Empty : segment.Substring(spaceIndex).TrimStart(' ', '\t');

        if (!StringTools.IsValidRFC7230Token(schemeWord))
            throw Err(AuthHeaderErrorCodes.InvalidAuthParam,
                $"'{schemeWord}' is not a valid scheme token.", lineIndex, basePosition);

        var challenge = Challenge.Create(schemeWord);
        if (remainder.Length == 0)
            return challenge;

        int remainderBasePosition = basePosition + (segment.Length - remainder.Length);
        if (LooksLikeAuthParam(remainder, out int remEq))
        {
            var (name, value) = ParseNameValue(remainder, remEq, lineIndex, remainderBasePosition);
            return challenge.WithParamCore(name, value);
        }

        /* Not an auth-param, so it must be a token68 -- and, unlike auth-params,
         * a token68 cannot itself contain embedded whitespace. */
        if (IndexOfOws(remainder) >= 0 || !StringTools.IsValidToken68(remainder))
            throw Err(AuthHeaderErrorCodes.InvalidToken68,
                $"'{remainder}' is not a valid token68 value.", lineIndex, remainderBasePosition);

        return challenge.WithToken68Core(remainder);
    }

    /// <summary>
    /// Whether <paramref name="s"/> is shaped like a genuine <c>token BWS "=" BWS value</c>
    /// auth-param, as opposed to a token68 that merely happens to contain trailing "="
    /// padding (e.g. "Rutabaga123=="). A top-level '=' only counts as introducing a
    /// value when something other than more '=' padding follows it.
    /// </summary>
    private static bool LooksLikeAuthParam(string s, out int equalsIndex)
    {
        equalsIndex = FindTopLevelEquals(s);
        if (equalsIndex < 0)
            return false;
        for (int i = equalsIndex + 1; i < s.Length; i++)
            if (s[i] != '=')
                return true;
        return false;
    }

    /// <summary>
    /// Whether a comma-separated segment continues the challenge already open, i.e. it is
    /// a bare <c>name BWS "=" ...</c> auth-param with nothing else before the name. A
    /// segment with a whitespace-separated word *before* that name (e.g. "Basic realm=x")
    /// is actually a new challenge's head, not a continuation -- token68/first-param pairs
    /// only ever appear directly after a scheme, never after a plain top-level comma.
    /// </summary>
    private static bool SegmentContinuesChallenge(string s, out int equalsIndex)
    {
        if (!LooksLikeAuthParam(s, out equalsIndex))
            return false;
        string namePart = s.Substring(0, equalsIndex).TrimEnd(' ', '\t');
        return IndexOfOws(namePart) < 0;
    }

    private static (string Name, string Value) ParseNameValue(string segment, int eqIndex, int lineIndex, int basePosition)
    {
        string namePart = segment.Substring(0, eqIndex).TrimEnd(' ', '\t');
        if (!StringTools.IsValidRFC7230Token(namePart))
            throw Err(AuthHeaderErrorCodes.InvalidAuthParam,
                $"'{namePart}' is not a valid parameter name.", lineIndex, basePosition);

        string valuePart = segment.Substring(eqIndex + 1).TrimStart(' ', '\t');
        int valueBasePosition = basePosition + eqIndex + 1 + (segment.Length - eqIndex - 1 - valuePart.Length);

        string value;
        if (valuePart.StartsWith("\"", StringComparison.Ordinal))
        {
            value = ParseQuotedString(valuePart, lineIndex, valueBasePosition, out int consumed);
            string rest = valuePart.Substring(consumed).Trim(' ', '\t');
            if (rest.Length > 0)
                throw Err(AuthHeaderErrorCodes.InvalidAuthParam,
                    $"Unexpected content '{rest}' after quoted value for '{namePart}'.", lineIndex, valueBasePosition);
        }
        else
        {
            value = valuePart;
            if (!StringTools.IsValidRFC7230Token(value))
                throw Err(AuthHeaderErrorCodes.InvalidAuthParam,
                    $"'{value}' is not a valid value for parameter '{namePart}'.", lineIndex, valueBasePosition);
        }

        return (namePart, value);
    }

    private static string ParseQuotedString(string text, int lineIndex, int basePosition, out int consumed)
    {
        var result = new StringBuilder();
        bool afterBackslash = false;
        for (int i = 1; i < text.Length; i++)
        {
            char c = text[i];
            if (afterBackslash)
            {
                result.Append(c);
                afterBackslash = false;
            }
            else if (c == '\\')
            {
                afterBackslash = true;
            }
            else if (c == '"')
            {
                consumed = i + 1;
                return result.ToString();
            }
            else
            {
                result.Append(c);
            }
        }
        throw Err(AuthHeaderErrorCodes.UnterminatedQuotedString, "Unterminated quoted string.", lineIndex, basePosition);
    }

    private static List<(int Start, int Length)> SplitTopLevelCommaSegments(string line, int lineIndex)
    {
        var result = new List<(int, int)>();
        int start = 0;
        bool inQuotes = false;
        bool afterBackslash = false;
        int quoteStart = -1;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (inQuotes)
            {
                if (afterBackslash)
                    afterBackslash = false;
                else if (c == '\\')
                    afterBackslash = true;
                else if (c == '"')
                    inQuotes = false;
                continue;
            }

            if (c == '"')
            {
                inQuotes = true;
                quoteStart = i;
            }
            else if (c == ',')
            {
                result.Add((start, i - start));
                start = i + 1;
            }
        }

        if (inQuotes)
            throw Err(AuthHeaderErrorCodes.UnterminatedQuotedString, "Unterminated quoted string.", lineIndex, quoteStart);

        result.Add((start, line.Length - start));
        return result;
    }

    private static int FindTopLevelEquals(string s)
    {
        bool inQuotes = false;
        bool afterBackslash = false;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (inQuotes)
            {
                if (afterBackslash)
                    afterBackslash = false;
                else if (c == '\\')
                    afterBackslash = true;
                else if (c == '"')
                    inQuotes = false;
                continue;
            }

            if (c == '"')
                inQuotes = true;
            else if (c == '=')
                return i;
        }
        return -1;
    }

    private static bool IsOws(char c) => c == ' ' || c == '\t';

    private static int IndexOfOws(string s)
    {
        for (int i = 0; i < s.Length; i++)
            if (IsOws(s[i]))
                return i;
        return -1;
    }

    private static AuthHeaderParseException Err(string code, string message, int lineIndex, int position)
        => new(code, message, lineIndex, position);
}
