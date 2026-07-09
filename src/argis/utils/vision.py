"""Face detection and reverse image search."""

import asyncio
from pathlib import Path
from typing import Optional
from urllib.parse import quote

try:
    import cv2
    _has_cv2 = True
except ImportError:
    _has_cv2 = False


FaceBox = tuple[int, int, int, int]


def detect_faces(image_path: str | Path) -> list[FaceBox]:
    if not _has_cv2:
        return []
    img = cv2.imread(str(image_path))
    if img is None:
        return []
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    cascade = cv2.CascadeClassifier(
        cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    )
    faces = cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))
    return [(int(x), int(y), int(w), int(h)) for x, y, w, h in faces]


def crop_face(image_path: str | Path, face: FaceBox, output_dir: Path, index: int) -> Path:
    from PIL import Image
    img = Image.open(str(image_path))
    if img.mode == "RGBA":
        img = img.convert("RGB")
    elif img.mode != "RGB":
        img = img.convert("RGB")
    x, y, w, h = face
    cropped = img.crop((x, y, x + w, y + h))
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"face_{index}.jpg"
    cropped.save(path, "JPEG")
    return path


def get_face_bytes(image_path: str | Path, face: FaceBox) -> Optional[bytes]:
    from PIL import Image
    from io import BytesIO
    img = Image.open(str(image_path))
    if img.mode == "RGBA":
        img = img.convert("RGB")
    elif img.mode != "RGB":
        img = img.convert("RGB")
    x, y, w, h = face
    x = max(0, x)
    y = max(0, y)
    w = min(w, img.width - x)
    h = min(h, img.height - y)
    if w <= 0 or h <= 0:
        return None
    cropped = img.crop((x, y, x + w, y + h))
    buf = BytesIO()
    cropped.save(buf, "JPEG")
    return buf.getvalue()


ENGINES: dict[str, dict] = {
    "google": {
        "url": "https://lens.google.com/upload",
        "upload": "https://www.google.com/searchbyimage/upload",
        "field": "encoded_image",
    },
    "yandex": {
        "url": "https://yandex.com/images/search?rpt=imageview",
        "upload": "https://yandex.com/images/search?rpt=imageview",
        "field": "upfile",
    },
    "bing": {
        "url": "https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIIRP",
        "upload": "https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIIRP",
        "field": "imageBin",
    },
    "tineye": {
        "url": "https://tineye.com/search",
        "upload": "https://tineye.com/search",
        "field": "image",
    },
    "saucenao": {
        "url": "https://saucenao.com/search.php",
        "upload": None,
        "field": None,
    },
    "iqdb": {
        "url": "https://iqdb.org/",
        "upload": None,
        "field": None,
    },
    "imgops": {
        "url": "https://imgops.com/",
        "upload": None,
        "field": None,
    },
}


def get_engine_url(engine: str) -> Optional[str]:
    info = ENGINES.get(engine)
    return info["url"] if info else None


def upload_to_engine(image_bytes: bytes, engine: str = "google") -> Optional[str]:
    info = ENGINES.get(engine)
    if not info or not info.get("upload"):
        return None
    try:
        import httpx
        resp = httpx.post(
            info["upload"],
            files={info["field"]: ("image.jpg", image_bytes, "image/jpeg")},
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            follow_redirects=False,
            timeout=30,
        )
        search_url = resp.headers.get("location")
        if search_url and search_url.startswith("http"):
            return search_url
        return None
    except Exception:
        return None


async def identify_from_search(
    search_url: str,
    engine: str = "google",
) -> Optional[str]:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        pass

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--disable-blink-features=AutomationControlled"],
            )
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 800},
            )
            page = await context.new_page()
            await page.evaluate("Object.defineProperty(navigator, 'webdriver', {get: () => false})")
            await page.goto(search_url, wait_until="networkidle", timeout=30000)
            await page.wait_for_timeout(5000)
            title = await page.title()
            body = await page.evaluate("() => document.body?.innerText || ''")
            await browser.close()

        if "unusual traffic" in body.lower():
            return None

        suffix = " - Bing" if engine == "bing" else " - Google Search"
        name = title.replace(suffix, "").replace(" - Google Zoeken", "").strip()
        if name and not name.startswith("http") and not name.startswith("Google") and len(name) < 100:
            return name
        return None
    except Exception:
        pass


HOSTING_SERVICES = [
    {
        "name": "telegra.ph",
        "url": "https://telegra.ph/upload",
        "field": "file",
        "parse": lambda data: "https://telegra.ph" + data[0]["src"],
    },
    {
        "name": "img402.dev",
        "url": "https://img402.dev/api/free",
        "field": "image",
        "parse": lambda data: data["url"],
    },
]


def host_image(image_bytes: bytes) -> Optional[str]:
    for svc in HOSTING_SERVICES:
        try:
            import httpx
            resp = httpx.post(
                svc["url"],
                files={svc["field"]: ("image.jpg", image_bytes, "image/jpeg")},
                timeout=15,
            )
            if resp.is_success:
                url = svc["parse"](resp.json())
                if url:
                    return url
        except Exception:
            continue
    return None


def google_reverse_search_by_url(image_url: str) -> Optional[str]:
    try:
        import httpx
        from bs4 import BeautifulSoup
    except ImportError:
        return None

    try:
        search_url = (
            f"https://images.google.com/searchbyimage"
            f"?safe=off&sbisrc=tg&image_url={quote(image_url)}"
        )
        resp = httpx.get(
            search_url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Linux; Android 6.0.1; SM-G920V Build/MMB29K) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/52.0.2743.98 Mobile Safari/537.36"
                ),
            },
            follow_redirects=True,
            timeout=30,
        )
        if not resp.is_success:
            return None

        html = resp.text
        if "unusual traffic" in html.lower():
            return None

        soup = BeautifulSoup(html, "lxml")

        # Strategy 1: input.gLFyf value attribute (Node API approach)
        inp = soup.select_one("input.gLFyf")
        if inp and inp.get("value"):
            return inp["value"].strip()

        # Strategy 2: input[name=q] value attribute
        inp = soup.select_one('input[name="q"]')
        if inp and inp.get("value"):
            return inp["value"].strip()

        # Strategy 3: div.r5a77d text (result banner)
        div = soup.select_one("div.r5a77d")
        if div:
            text = div.get_text(strip=True)
            text = text.replace("Results for ", "").strip()
            if text:
                return text

        # Strategy 4: Look for any "best guess" visible text
        for sel in [".Vkn1n", ".tGvsQd", '[data-attrid="title"]', ".kno-ecr-pt"]:
            el = soup.select_one(sel)
            if el:
                text = el.get_text(strip=True)
                if text and len(text) < 100:
                    return text

        return None
    except Exception:
        return None


def identify_face(face_bytes: bytes) -> Optional[str]:
    url = host_image(face_bytes)
    if url:
        result = google_reverse_search_by_url(url)
        if result:
            return result
    return None


INSIGHT_MODEL = None


def _get_insight_model():
    global INSIGHT_MODEL
    if INSIGHT_MODEL is None:
        import insightface
        INSIGHT_MODEL = insightface.app.FaceAnalysis(name="buffalo_l")
        INSIGHT_MODEL.prepare(ctx_id=0)
    return INSIGHT_MODEL


def _get_embedding(image_path: str):
    import cv2
    model = _get_insight_model()
    img = cv2.imread(image_path)
    if img is None:
        return None
    faces = model.get(img)
    if not faces:
        return None
    return faces[0].embedding


def find_celebrity_lookalike(image_path: str) -> Optional[dict]:
    try:
        import numpy as np
        import insightface
    except ImportError:
        return None

    try:
        query_emb = _get_embedding(image_path)
        if query_emb is None:
            return None

        db = celebrity_db_path()
        best_match = None
        best_name = None
        best_score = -1

        for person_dir in sorted(Path(db).iterdir()):
            if not person_dir.is_dir():
                continue
            for img_file in person_dir.iterdir():
                if img_file.suffix.lower() not in (".jpg", ".jpeg", ".png"):
                    continue
                ref_emb = _get_embedding(str(img_file))
                if ref_emb is None:
                    continue
                import numpy as np
                sim = float(np.dot(query_emb, ref_emb) / (np.linalg.norm(query_emb) * np.linalg.norm(ref_emb)))
                if sim > best_score:
                    best_score = sim
                    best_name = person_dir.name

        if best_name and best_score > 0.3:
            return {
                "identity": best_name,
                "similarity": f"{best_score * 100:.1f}%",
            }
        return None
    except Exception:
        return None


def celebrity_db_path() -> str:
    base = Path.home() / ".argis" / "celebrities"
    base.mkdir(parents=True, exist_ok=True)
    return str(base)


def analyze_face(image_path: str) -> Optional[dict]:
    try:
        import insightface
        import cv2
    except ImportError:
        return None
    try:
        model = _get_insight_model()
        img = cv2.imread(image_path)
        if img is None:
            return None
        faces = model.get(img)
        if not faces:
            return None
        face = faces[0]
        result = {
            "detected": True,
            "age": float(face.age) if hasattr(face, "age") else None,
            "gender": face.gender if hasattr(face, "gender") else None,
        }
        return result
    except Exception:
        return None


def setup_celebrity_db(force: bool = False) -> int:
    db_path = Path(celebrity_db_path())
    if db_path.exists() and not force:
        count = 0
        for person_dir in db_path.iterdir():
            if person_dir.is_dir():
                count += len([f for f in person_dir.iterdir() if f.suffix.lower() in (".jpg", ".jpeg", ".png")])
        if count > 0:
            return count

    print("[dim]Add your own celebrity reference images:[/dim]")
    print(f"  Create a folder: [cyan]{db_path / 'PersonName'}[/cyan]")
    print(f"  Put face images inside (jpg/png)")
    print(f"  Then run: [cyan]argis scan-face photo.jpg --identify --offline[/cyan]")
    print()
    return 0
