from pathlib import Path
import re

root = Path('python_modules')
for p in root.rglob('*.py'):
    text = p.read_text(encoding='utf-8')
    orig = text
    # Remove leading module docstring
    docstring_match = re.match(r'^(\s*#.*\n|\s*)*(?P<quote>"""|\'\'\')(?:.|\n)*?\1', text)
    if docstring_match and text[:docstring_match.end()].strip().startswith(('"""', "'''")):
        text = text[docstring_match.end():]
    # Remove leading comment block
    text = re.sub(r'^(?:\s*#.*\n)+', '', text)
    # Remove leading blank lines
    text = re.sub(r'\A[\r\n]+', '', text)
    if text != orig:
        p.write_text(text, encoding='utf-8')
        print(f'Cleaned {p}')
