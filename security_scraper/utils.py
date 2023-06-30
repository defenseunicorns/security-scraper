import re
import lxml.etree


# https://stackoverflow.com/a/75089993/1108997
class RegexEqual(str):
    def __eq__(self, pattern):
        return bool(re.search(pattern, self))


def to_plaintext(selector_list, delimiter_html=""):
    """
    Convert a Selector or Selector list to plain text and convert <br> and <p> to newlines
    """

    text = ""
    for selector in selector_list.css("::text, br, p"):
        if (
            isinstance(selector.root, lxml.etree.ElementBase)
            and selector.root.tag == "p"
        ):
            text += "\n\n"
        elif (
            isinstance(selector.root, lxml.etree.ElementBase)
            and selector.root.tag == "br"
        ):
            text += "\n"
        else:
            # This is mostly to convert non-space whitespace (mostly newlines) into spaces
            text += re.sub(r"\s+", " ", selector.get())
    # Collapse repeated spaces or newlines into one (this must be done in a separate step because whitespace may be spread across multiple text nodes)
    return re.sub(r"( )+|(?:(\n\n)\n+)", r"\1\2", text.strip())


CVE_REGEX = r"(?i)CVE-\d{4}-\d{4,7}"


def slug(string, delimiter="_"):
    return re.sub(r"\W+", delimiter, string.lower()).strip("_")
