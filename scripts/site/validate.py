"""Validate the static GitHub Pages site under site/ with only the standard library.

Run with python3 -I. --self-test checks that the validator rejects broken copies.
"""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit
import argparse
import json
import re
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
ORIGIN = 'https://avhn.github.io'
BASE = '/secret/'
SITE_URL = ORIGIN + BASE
# Indexable pages in sitemap order, then pages excluded from the sitemap.
PAGES = ('index.html', 'setup/index.html', 'tools/index.html', 'security/index.html')
NOINDEX = ('404.html',)
REQUIRED_FILES = ('.nojekyll', 'robots.txt', 'sitemap.xml', 'llms.txt', 'assets/style.css',
                  'assets/copy.js', 'assets/favicon.svg', 'assets/social.png')
REQUIRED_META = ('description', 'og:type', 'og:title', 'og:description', 'og:url', 'og:image',
                 'og:image:alt', 'twitter:card', 'twitter:title', 'twitter:description',
                 'twitter:image')
# Em dash, en dash, middle dot and emoji or pictograph ranges.
EM_DASH, EN_DASH, MIDDLE_DOT, BULLET = chr(0x2014), chr(0x2013), chr(0xb7), chr(0x2022)
FORBIDDEN = re.compile('[' + EN_DASH + EM_DASH + MIDDLE_DOT + BULLET + chr(0x2600) + '-' + chr(0x27bf)
                       + chr(0x1f000) + '-' + chr(0x1faff) + ']')
RAW_MAIN = 'https://raw.githubusercontent.com/avhn/secret/main/'
# Pages whose installer-script URLs must carry the current release version.
INSTALLER_PAGES = ('index.html', 'setup/index.html')
INSTALLER_URL = re.compile(r'https://raw\.githubusercontent\.com/avhn/secret/v([^/]+)/install\.(?:sh|ps1)')
MANIFEST_TEMPLATE = 'packaging/mcpb/manifest.template.json'


def release_version(repo):
    """The coordinated release identity, read from the MCPB manifest template with stdlib json."""
    data = json.loads((repo / MANIFEST_TEMPLATE).read_text(encoding='utf-8'))
    version = data.get('version')
    if not isinstance(version, str) or not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError(f'{MANIFEST_TEMPLATE}: expected a strict release version')
    return version


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.ids, self.links, self.meta = [], [], [], {}
        self.canonical, self.stylesheets, self.scripts, self.icons = [], [], [], []
        self.title, self.h1, self.lang, self.ld = '', 0, None, []
        self.faq, self.in_faq, self.capture, self.text = [], 0, None, []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag not in ('meta', 'link', 'img', 'br', 'source', 'rect', 'path', 'input'):
            self.stack.append(tag)
        if tag == 'html':
            self.lang = attrs.get('lang')
        if attrs.get('id'):
            self.ids.append(attrs['id'])
        if tag == 'h1':
            self.h1 += 1
        if tag == 'meta':
            key = attrs.get('name') or attrs.get('property')
            if key:
                self.meta.setdefault(key, []).append(attrs.get('content') or '')
        if tag == 'link':
            rel = attrs.get('rel', '')
            if rel == 'canonical':
                self.canonical.append(attrs.get('href'))
            elif rel == 'stylesheet':
                self.stylesheets.append(attrs.get('href'))
            elif rel == 'icon':
                self.icons.append(attrs.get('href'))
        if tag == 'script':
            if attrs.get('src'):
                self.scripts.append(attrs['src'])
            if attrs.get('type') == 'application/ld+json':
                self.capture = 'ld'
                self.text = []
        for name in ('href', 'src'):
            if attrs.get(name) and not (tag == 'link' and attrs.get('rel') == 'canonical'):
                self.links.append(attrs[name])
        if tag == 'section' and 'faq' in (attrs.get('class') or '').split():
            self.in_faq = len(self.stack)
        if self.in_faq and tag in ('h3', 'p'):
            self.capture = tag
            self.text = []

    def handle_endtag(self, tag):
        if self.capture == 'ld' and tag == 'script':
            self.ld.append(''.join(self.text))
            self.capture = None
        elif self.capture in ('h3', 'p') and tag == self.capture:
            value = ' '.join(''.join(self.text).split())
            if tag == 'h3':
                self.faq.append([value, None])
            elif self.faq and self.faq[-1][1] is None:
                self.faq[-1][1] = value
            self.capture = None
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()
        elif tag in self.stack:
            while self.stack and self.stack.pop() != tag:
                pass
        if self.in_faq and len(self.stack) < self.in_faq:
            self.in_faq = 0

    def handle_data(self, data):
        if self.stack and self.stack[-1] == 'title':
            self.title += data
        if self.capture:
            self.text.append(data)


def page_url(name):
    return SITE_URL + ('' if name == 'index.html' else name[:-len('index.html')]
                       if name.endswith('/index.html') else name)


def resolve(site, url):
    """Map a /secret/ URL path to a file under site, or None."""
    path = unquote(urlsplit(url).path)
    if not path.startswith(BASE):
        return None
    relative = path[len(BASE):]
    if '..' in relative.split('/'):
        return None
    target = site / relative
    if relative == '' or relative.endswith('/'):
        target = target / 'index.html'
    return target if target.is_file() else None


def validate(site, repo=ROOT):
    errors = []

    def fail(message):
        errors.append(message)

    for name in REQUIRED_FILES:
        if not (site / name).is_file():
            fail(f'missing required file: {name}')
    html_files = sorted(str(path.relative_to(site)).replace('\\', '/') for path in site.rglob('*.html'))
    if html_files != sorted(PAGES + NOINDEX):
        fail(f'unexpected HTML pages: {html_files}')

    for path in sorted(site.rglob('*')):
        if path.is_file() and path.suffix in ('.html', '.css', '.js', '.txt', '.xml', '.svg'):
            text = path.read_text(encoding='utf-8')
            for number, line in enumerate(text.splitlines(), 1):
                if FORBIDDEN.search(line):
                    fail(f'{path.relative_to(site)}:{number}: em/en dash, middle dot or emoji')

    parsed = {}
    for name in PAGES + NOINDEX:
        path = site / name
        if not path.is_file():
            continue
        page = Page()
        try:
            page.feed(path.read_text(encoding='utf-8'))
            page.close()
        except Exception as error:  # HTMLParser raises only on internal faults.
            fail(f'{name}: does not parse: {error}')
            continue
        parsed[name] = page
        expected = page_url(name)
        if page.lang != 'en':
            fail(f'{name}: html lang must be en')
        if not page.title.strip():
            fail(f'{name}: missing title')
        if page.h1 != 1:
            fail(f'{name}: expected one h1, found {page.h1}')
        for key in REQUIRED_META:
            values = page.meta.get(key, [])
            if len(values) != 1 or not values[0].strip():
                fail(f'{name}: expected one nonempty {key} meta tag')
        if page.meta.get('og:title') != [page.title.strip()]:
            fail(f'{name}: og:title differs from title')
        if page.meta.get('og:description') != page.meta.get('description'):
            fail(f'{name}: og:description differs from description')
        if page.meta.get('og:url') != [expected]:
            fail(f'{name}: og:url must be {expected}')
        if name in PAGES:
            if page.canonical != [expected]:
                fail(f'{name}: canonical must be {expected}')
        elif page.meta.get('robots') != ['noindex'] or page.canonical:
            fail(f'{name}: must be noindex without canonical')
        for image in page.meta.get('og:image', []) + page.meta.get('twitter:image', []):
            if not image.startswith(SITE_URL) or resolve(site, urlsplit(image).path) is None:
                fail(f'{name}: social image does not resolve: {image}')
        if page.stylesheets != [BASE + 'assets/style.css']:
            fail(f'{name}: must reference {BASE}assets/style.css')
        if page.scripts != [BASE + 'assets/copy.js']:
            fail(f'{name}: must reference {BASE}assets/copy.js')
        if page.icons != [BASE + 'assets/favicon.svg']:
            fail(f'{name}: must reference {BASE}assets/favicon.svg')
        if len(page.ids) != len(set(page.ids)):
            fail(f'{name}: duplicate ids')
        for block in page.ld:
            try:
                json.loads(block)
            except ValueError:
                fail(f'{name}: invalid JSON-LD')

    try:
        version = release_version(repo)
    except (OSError, ValueError) as error:
        version = None
        fail(f'cannot read the release version: {error}')
    for name, page in parsed.items():
        for block in page.ld:
            try:
                data = json.loads(block)
            except ValueError:
                continue
            if data.get('@type') != 'SoftwareApplication':
                continue
            if data.get('name') != 'Secret':
                fail(f'{name}: SoftwareApplication name must be Secret')
            if version is not None and data.get('softwareVersion') != version:
                fail(f'{name}: softwareVersion {data.get("softwareVersion")!r} differs from {MANIFEST_TEMPLATE} {version}')
        if name in INSTALLER_PAGES and version is not None:
            text = (site / name).read_text(encoding='utf-8')
            found = INSTALLER_URL.findall(text)
            if not found:
                fail(f'{name}: expected installer-script URLs')
            for pinned in found:
                if pinned != version:
                    fail(f'{name}: installer-script URL pins v{pinned}, expected v{version}')

    for name, page in parsed.items():
        for link in page.links:
            parts = urlsplit(link)
            if parts.scheme in ('http', 'https', 'mailto'):
                if link.startswith(ORIGIN) and not link.startswith(SITE_URL):
                    fail(f'{name}: link outside {BASE}: {link}')
                continue
            if parts.scheme or parts.netloc:
                fail(f'{name}: unsupported link: {link}')
                continue
            if not parts.path:
                target_name, target = name, parsed.get(name)
            else:
                if not parts.path.startswith(BASE):
                    fail(f'{name}: internal link must start with {BASE}: {link}')
                    continue
                file = resolve(site, parts.path)
                if file is None:
                    fail(f'{name}: broken link: {link}')
                    continue
                target_name = str(file.relative_to(site)).replace('\\', '/')
                target = parsed.get(target_name)
            if parts.fragment and (target is None or unquote(parts.fragment) not in target.ids):
                fail(f'{name}: missing anchor: {link}')

    security = parsed.get('security/index.html')
    if security is not None:
        entries = []
        for block in security.ld:
            try:
                data = json.loads(block)
            except ValueError:
                continue
            if data.get('@type') == 'FAQPage':
                entries = [[item.get('name'), item.get('acceptedAnswer', {}).get('text')]
                           for item in data.get('mainEntity', [])]
        if not entries or entries != security.faq:
            fail('security/index.html: FAQPage JSON-LD must match the visible FAQ')

    sitemap = site / 'sitemap.xml'
    if sitemap.is_file():
        locations = re.findall(r'<loc>([^<]+)</loc>', sitemap.read_text(encoding='utf-8'))
        if locations != [page_url(name) for name in PAGES]:
            fail(f'sitemap.xml must list exactly {[page_url(name) for name in PAGES]}')
    robots = site / 'robots.txt'
    if robots.is_file() and f'Sitemap: {SITE_URL}sitemap.xml' not in robots.read_text(encoding='utf-8'):
        fail('robots.txt must reference the sitemap')
    llms = site / 'llms.txt'
    if llms.is_file():
        for url in re.findall(r'\]\((https://[^)\s]+)\)', llms.read_text(encoding='utf-8')):
            if url.startswith(RAW_MAIN):
                if not (repo / url[len(RAW_MAIN):].split('#')[0]).is_file():
                    fail(f'llms.txt: linked file is missing from the repository: {url}')
            else:
                fail(f'llms.txt: links must point at raw documents on main: {url}')
    return errors


def self_test():
    def mutate(site, name, old, new):
        path = site / name
        text = path.read_text(encoding='utf-8')
        if old not in text:
            raise SystemExit(f'FAIL self-test: fixture text not found in {name}: {old!r}')
        path.write_text(text.replace(old, new, 1), encoding='utf-8')

    cases = {
        'second h1': ('index.html', '</main>', '<h1>Again</h1></main>'),
        'em dash': ('tools/index.html', '</main>', '<p>a ' + EM_DASH + ' b</p></main>'),
        'middle dot': ('llms.txt', '# Secret', '# Secret ' + MIDDLE_DOT + ' x'),
        'broken link': ('index.html', 'href="/secret/setup/"', 'href="/secret/missing/"'),
        'missing anchor': ('setup/index.html', 'href="#install"', 'href="#nowhere"'),
        'missing cross-page anchor': ('index.html', 'href="/secret/setup/"', 'href="/secret/setup/#nowhere"'),
        'relative link': ('index.html', 'href="/secret/tools/"', 'href="tools/"'),
        'missing copy.js': ('setup/index.html', '<script src="/secret/assets/copy.js" defer></script>', ''),
        'missing canonical': ('tools/index.html', '<link rel="canonical" href="https://avhn.github.io/secret/tools/">', ''),
        'missing og:image': ('security/index.html', '<meta property="og:image" ', '<meta property="og:imagex" '),
        'sitemap drift': ('sitemap.xml', '</urlset>', '  <url><loc>https://avhn.github.io/secret/extra/</loc></url>\n</urlset>'),
        'faq drift': ('security/index.html', '<h3 id="question-1">What is Secret?</h3>', '<h3 id="question-1">What is it?</h3>'),
        'llms missing file': ('llms.txt', 'docs/setup.md', 'docs/missing.md'),
    }
    version = release_version(ROOT)
    bumped = version[:-1] + str((int(version[-1]) + 1) % 10)
    for name in PAGES + NOINDEX:
        cases[f'softwareVersion drift in {name}'] = (
            name, f'"softwareVersion":"{version}"', f'"softwareVersion":"{bumped}"')
        cases[f'lowercase SoftwareApplication name in {name}'] = (name, '"name":"Secret"', '"name":"secret"')
    for name in INSTALLER_PAGES:
        for script in ('install.sh', 'install.ps1'):
            cases[f'{script} URL version drift in {name}'] = (
                name, f'/v{version}/{script}', f'/v{bumped}/{script}')
    with tempfile.TemporaryDirectory(prefix='secret-site-') as temporary:
        clean = Path(temporary) / 'clean'
        shutil.copytree(ROOT / 'site', clean)
        errors = validate(clean)
        if errors:
            raise SystemExit('FAIL self-test: the checked-in site is not clean:\n' + '\n'.join(errors))
        for index, (label, (name, old, new)) in enumerate(cases.items()):
            broken = Path(temporary) / f'case-{index}'
            shutil.copytree(clean, broken)
            mutate(broken, name, old, new)
            if not validate(broken):
                raise SystemExit(f'FAIL self-test: validator accepted {label}')
        missing = Path(temporary) / 'missing-nojekyll'
        shutil.copytree(clean, missing)
        (missing / '.nojekyll').unlink()
        if not validate(missing):
            raise SystemExit('FAIL self-test: validator accepted a missing .nojekyll')
        # A drifted manifest template must fail every page's version identity.
        repo = Path(temporary) / 'repo'
        (repo / MANIFEST_TEMPLATE).parent.mkdir(parents=True)
        for document in ('docs/setup.md', 'docs/install.md', 'docs/usage.md', 'docs/windows.md', 'docs/age.md',
                         'docs/pass.md', 'SECURITY.md', 'skills/secrets/SKILL.md'):
            (repo / document).parent.mkdir(parents=True, exist_ok=True)
            (repo / document).write_text('synthetic\n', encoding='utf-8')
        (repo / MANIFEST_TEMPLATE).write_text(json.dumps({'version': bumped}), encoding='utf-8')
        if not validate(clean, repo):
            raise SystemExit('FAIL self-test: validator accepted a manifest template version drift')
    print(f'PASS: validator self-test rejected {len(cases) + 2} broken copies')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true', help='Check that broken copies are rejected')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    errors = validate(ROOT / 'site')
    if errors:
        for error in errors:
            print(f'FAIL: {error}', file=sys.stderr)
        return 1
    print(f'PASS: site has {len(PAGES) + len(NOINDEX)} valid pages, resolved links and an exact sitemap')
    return 0


if __name__ == '__main__':
    sys.exit(main())
