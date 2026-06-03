"""验证码绕过工具：图形验证码 OCR + 滑块缺口检测 + 拟人轨迹生成。

基于 ddddocr (https://github.com/sml2h3/ddddocr)，离线本地运行，无需 API key。

用法:
  # 模块调用
  from captcha_bypass import ocr, slide_match, slide_comparison, generate_track

  text = ocr("captcha.png")
  result = slide_match("slider.png", "background.png")
  track = generate_track(result["target_x"])

  # Playwright/Scrapling 页面级自动解决
  from captcha_bypass import auto_solve_captcha
  # 作为 StealthyFetcher 的 page_action 回调：
  StealthyFetcher.fetch(url, page_action=auto_solve_captcha, ...)

  # 命令行: 图形验证码 OCR
  python TOOLS/captcha_bypass.py ocr captcha.png

  # 命令行: 滑块缺口定位 (边缘匹配)
  python TOOLS/captcha_bypass.py slide-match slider.png background.png

  # 命令行: 滑块缺口定位 (图像差分)
  python TOOLS/captcha_bypass.py slide-compare gap.png full.png

输出格式: JSON 到 stdout, 错误到 stderr
"""

import json
import sys
import time
from pathlib import Path
from typing import Any, Sequence

# 延迟导入，减少 CLI --help 的启动时间
_ddddocr = None
_DdddOcr = None


def _get_ddddocr():
    global _ddddocr, _DdddOcr
    if _DdddOcr is None:
        import ddddocr as _ddddocr

        _DdddOcr = _ddddocr.DdddOcr
    return _ddddocr, _DdddOcr


# ---------------------------------------------------------------------------
# 单例（复用 DdddOcr 实例，避免重复加载模型）
# ---------------------------------------------------------------------------

_ocr_instance = None
_slide_instance = None
_det_instance = None


def _get_ocr():
    global _ocr_instance
    if _ocr_instance is None:
        _, DdddOcr = _get_ddddocr()
        _ocr_instance = DdddOcr(det=False, ocr=True)
    return _ocr_instance


def _get_slide():
    global _slide_instance
    if _slide_instance is None:
        _, DdddOcr = _get_ddddocr()
        _slide_instance = DdddOcr(det=False, ocr=False)
    return _slide_instance


def _get_det():
    global _det_instance
    if _det_instance is None:
        _, DdddOcr = _get_ddddocr()
        _det_instance = DdddOcr(det=True, ocr=False)
    return _det_instance


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------


def _to_bytes(input_data):
    """接受文件路径或 bytes，统一返回 bytes。"""
    if isinstance(input_data, (str, Path)):
        return Path(input_data).read_bytes()
    if isinstance(input_data, bytes):
        return input_data
    raise TypeError(f"Expected str, Path, or bytes, got {type(input_data)}")


# ---------------------------------------------------------------------------
# 核心 API
# ---------------------------------------------------------------------------


def ocr(image, beta=False, png_fix=False):
    """图形验证码 OCR 识别。

    参数:
      image: 图片文件路径或 bytes
      beta: True 启用第二套 OCR 模型（对某些验证码效果更好）
      png_fix: True 启用透明 PNG 修复

    返回: 识别出的文字 (str)
    """
    image_bytes = _to_bytes(image)
    ocr_obj = _get_ocr()
    # ddddocr 的 classification 不支持 beta 切换，需要单独建实例
    if beta:
        _, DdddOcr = _get_ddddocr()
        beta_ocr = DdddOcr(det=False, ocr=True, beta=True)
        return beta_ocr.classification(image_bytes, png_fix=png_fix)
    return ocr_obj.classification(image_bytes, png_fix=png_fix)


def ocr_with_fallback(image, beta=False, png_fix=False):
    """OCR 识别，ddddocr 失败后自动调用 vision model 兜底。

    返回: (text: str, source: "ddddocr"|"vision"|"failed")
    """
    # Step 1: ddddocr 主力
    text = ocr(image, beta=beta, png_fix=png_fix)
    if text and len(text.strip()) >= 2:
        return text.strip(), "ddddocr"

    # Step 2: vision model 兜底
    try:
        import sys

        sys.path.insert(0, str(Path(__file__).resolve().parent / "mcp"))
        from vision import ocr_captcha

        image_path = image if isinstance(image, str) else None
        if image_path and Path(image_path).exists():
            result = ocr_captcha(image_path)
            if result.get("success") and result.get("content"):
                return result["content"].strip(), f"vision({result.get('provider', '?')})"
    except ImportError:
        pass

    return text.strip() if text else "", "failed"


def slide_match(target, background, simple_target=False):
    """滑块缺口定位 —— 边缘匹配算法（算法1）。

    适用于能分别获取透明滑块图和带缺口背景图的场景。

    参数:
      target: 透明滑块图片（文件路径或 bytes）
      background: 带缺口的背景图（文件路径或 bytes）
      simple_target: True 使用简化匹配（滑块边缘更清晰时）

    返回: {"target_x": int, "target_y": int}
      target_x, target_y 是滑块应滑动的目标位置（左上角坐标）
    """
    target_bytes = _to_bytes(target)
    bg_bytes = _to_bytes(background)
    slide = _get_slide()
    result = slide.slide_match(target_bytes, bg_bytes, simple_target=simple_target)

    # ddddocr 返回 {"target": [x1, y1, x2, y2]} 或类似结构
    if isinstance(result, dict) and "target" in result:
        t = result["target"]
        if isinstance(t, (list, tuple)) and len(t) >= 2:
            return {"target_x": int(t[0]), "target_y": int(t[1])}
    return result


def slide_comparison(target, background):
    """滑块缺口定位 —— 图像差分算法（算法2）。

    适用于能获取两张完整页面截图（一张有缺口阴影、一张没有）的场景。

    参数:
      target: 有缺口阴影的图（文件路径或 bytes）
      background: 无缺口的完整图（文件路径或 bytes）

    返回: {"target_x": int, "target_y": int}
    """
    target_bytes = _to_bytes(target)
    bg_bytes = _to_bytes(background)
    slide = _get_slide()
    return slide.slide_comparison(target_bytes, bg_bytes)


def detect(image):
    """目标检测 —— 在图中找出文字/物体区域。

    参数:
      image: 图片文件路径或 bytes

    返回: 检测到的物体坐标列表 (list[dict])
    """
    image_bytes = _to_bytes(image)
    det = _get_det()
    return det.detection(image_bytes)


def ocr_probability(image, beta=False):
    """OCR 全字符概率输出（用于需要灵活限定字符集的场景）。

    返回: 全字符表概率 (dict)
    """
    image_bytes = _to_bytes(image)
    if beta:
        _, DdddOcr = _get_ddddocr()
        beta_ocr = DdddOcr(det=False, ocr=True, beta=True)
        return beta_ocr.classification(image_bytes, probability=True)
    return _get_ocr().classification(image_bytes, probability=True)


# ---------------------------------------------------------------------------
# 拟人滑动轨迹生成
# ---------------------------------------------------------------------------


def generate_track(
    distance: int,
    with_time: bool = True,
    overshoot: bool = True,
) -> Sequence:
    """生成拟人滑动轨迹。

    分四段：初始加速 → 中间匀速 → 末尾减速 → 微调回正

    参数:
      distance: 目标滑动距离（像素，通常来自 slide_match 的 target_x）
      with_time: 返回是否包含时间戳 (默认 True，适合 Playwright drag)
      overshoot: 是否模拟轻微过冲后回正 (默认 True，防检测)

    返回:
      - with_time=True: [(x, y, dt_ms), ...] 带时间间隔的轨迹
      - with_time=False: [(x, y), ...] 纯坐标轨迹
    """
    import random

    random.seed()

    if distance <= 0:
        return [(0, 0, 0)] if with_time else [(0, 0)]

    track: list[Any] = []
    x = 0.0
    y_jitter = 3  # 轻微 Y 轴抖动范围

    # 1. 初始加速段 (0% → ~25% 距离)
    accel_dist = distance * 0.25
    accel_steps = random.randint(8, 14)
    for i in range(accel_steps):
        progress = i / accel_steps
        x += (accel_dist / accel_steps) * (0.3 + 0.7 * progress)  # 加速
        y = random.uniform(-y_jitter, y_jitter)
        dt = random.randint(8, 18)
        if with_time:
            track.append((round(x, 1), round(y, 1), dt))
        else:
            track.append((round(x, 1), round(y, 1)))

    # 2. 匀速段 (~25% → ~65%)
    cruise_dist = distance * 0.40
    cruise_steps = random.randint(12, 20)
    for _ in range(cruise_steps):
        x += cruise_dist / cruise_steps * random.uniform(0.9, 1.1)
        y = random.uniform(-y_jitter, y_jitter)
        dt = random.randint(5, 12)
        if with_time:
            track.append((round(x, 1), round(y, 1), dt))
        else:
            track.append((round(x, 1), round(y, 1)))

    # 3. 减速段 (~65% → ~95%)
    decel_dist = distance * 0.30
    decel_steps = random.randint(10, 16)
    for i in range(decel_steps):
        progress = i / decel_steps
        x += (decel_dist / decel_steps) * (1.0 - 0.5 * progress)  # 减速
        y = random.uniform(-y_jitter, y_jitter)
        dt = random.randint(10, 25)
        if with_time:
            track.append((round(x, 1), round(y, 1), dt))
        else:
            track.append((round(x, 1), round(y, 1)))

    # 4. 微调段 (~95% → 目标)
    remaining = distance - x
    fine_steps = random.randint(3, 6)
    for i in range(fine_steps):
        progress = i / fine_steps
        x += remaining / fine_steps * random.uniform(0.6, 1.0)
        y = random.uniform(-2, 2)
        dt = random.randint(30, 60)
        if with_time:
            track.append((round(x, 1), round(y, 1), dt))
        else:
            track.append((round(x, 1), round(y, 1)))

    # 纠正最后一点到目标
    if abs(x - distance) > 2:
        if with_time:
            track.append((distance, 0, random.randint(20, 40)))
        else:
            track.append((distance, 0))

    # 5. 过冲回正（可选，模拟拖过头再拉回来）
    if overshoot and distance > 20:
        overshoot_amount = random.randint(2, 6)
        for ox in (distance + overshoot_amount, distance):
            if with_time:
                track.append((ox, 0, random.randint(15, 30)))
            else:
                track.append((ox, 0))

    return track


# ---------------------------------------------------------------------------
# Playwright Page 级别验证码检测与解决
# ---------------------------------------------------------------------------

# 常见验证码特征选择器
_CAPTCHA_PATTERNS = {
    "image": [
        'img[src*="captcha"]',
        'img[src*="Captcha"]',
        'img[src*="verify"]',
        'img[id*="captcha"]',
        'img[class*="captcha"]',
        'img[id*="verify"]',
        'img[class*="verify"]',
        'img[src*="code"]',
        'img[id*="codeImg"]',
        'img[src*="rand"]',
        'img[src*="valid"]',
        'img[class*="code"]',
        'img[id*="imgCode"]',
    ],
    "slider": [
        ".geetest_slider_button",
        ".geetest_slider_track",
        ".slider",
        '[class*="slider"]',
        '[id*="slider"]',
        ".captcha-slider",
        '[class*="slide"]',
        ".verify-box",
        '[class*="verify"]',
        ".nc_wrapper",
        ".nc_iconfont",
        ".captcha_verify",
        '[id*="drag"]',
        '[class*="drag"]',
    ],
    "input": [
        'input[id*="captcha"]',
        'input[name*="captcha"]',
        'input[id*="verify"]',
        'input[id*="code"]',
        'input[placeholder*="验证码"]',
        'input[placeholder*="captcha"]',
        'input[name*="valid"]',
        'input[name*="code"]',
        'input[class*="captcha"]',
        'input[id*="valid"]',
    ],
}


def detect_captcha_on_page(page):
    """检测页面是否存在验证码，返回验证码类型和元素信息。

    在 page_action 回调中调用，检查当前页面是否为验证码页面。

    返回: {"type": "image"|"slider"|None, "elements": {...}} 或 None
    """
    try:
        content = page.content()

        # 检查已知验证码特征
        has_slider = any(
            kw in content.lower()
            for kw in ("geetest", "slider", "slideverify", "dragverify", "nc_wrapper", "nc_iconfont")
        )
        has_captcha = any(
            kw in content.lower()
            for kw in ("captcha", "验证码", "verification code", "请输入验证码", "complete the security check")
        )

        if not has_slider and not has_captcha:
            return None

        # 确认滑块存在
        if has_slider:
            for sel in _CAPTCHA_PATTERNS["slider"]:
                elem = page.query_selector(sel)
                if elem and elem.is_visible():
                    return {"type": "slider", "selector": sel, "page": page}

        # 确认图形验证码存在
        if has_captcha:
            for sel in _CAPTCHA_PATTERNS["image"]:
                elem = page.query_selector(sel)
                if elem and elem.is_visible():
                    return {"type": "image", "selector": sel, "page": page}

        return None

    except Exception:
        return None


def solve_image_captcha_on_page(page, img_selector=None):
    """在 Playwright Page 上解决图形验证码。

    1. 定位验证码图片并截图
    2. OCR 识别
    3. 填入输入框
    4. 点击提交/确认按钮
    5. 等待页面更新

    返回: 识别出的文字 (str) 或 None
    """
    try:
        # 1. 定位验证码图片
        img = None
        if img_selector:
            img = page.query_selector(img_selector)
        else:
            for sel in _CAPTCHA_PATTERNS["image"]:
                img = page.query_selector(sel)
                if img and img.is_visible():
                    break

        if not img:
            return None

        img_bytes = img.screenshot()
        text = ocr(img_bytes)
        if not text or len(text) < 2:
            return None

        # 2. 定位输入框
        inp = None
        for sel in _CAPTCHA_PATTERNS["input"]:
            inp = page.query_selector(sel)
            if inp and inp.is_visible():
                break

        if not inp:
            # 尝试更宽泛的匹配：input 在验证码图片附近
            inp = page.query_selector('input[type="text"]')
            if inp:
                pass  # fallback 到第一个 text input

        if not inp:
            return None

        # 3. 填入
        inp.click()
        inp.fill("")
        inp.type(text, delay=30)

        # 4. 点击提交
        for btn_sel in (
            'button:has-text("提交")',
            'button:has-text("确定")',
            'button:has-text("Submit")',
            'input[type="submit"]',
            'button[type="submit"]',
        ):
            btn = page.query_selector(btn_sel)
            if btn and btn.is_visible():
                btn.click()
                break
        else:
            # 按回车提交
            inp.press("Enter")

        # 5. 等待页面更新
        try:
            page.wait_for_load_state("networkidle", timeout=10000)
        except Exception:
            page.wait_for_timeout(2000)

        return text

    except Exception:
        return None


def solve_slider_captcha_on_page(page, slider_selector=None, bg_selector=None):
    """在 Playwright Page 上解决滑块验证码。

    1. 截取滑块图 + 背景图
    2. slide_match 计算缺口位置
    3. 生成拟人轨迹
    4. 执行拖拽操作

    返回: {"success": bool, "target_x": int, "attempts": int}
    """
    import random

    # 滑块元素选择器
    slider_sels = _CAPTCHA_PATTERNS["slider"] if not slider_selector else [slider_selector]

    # 背景图选择器（通常是滑块所在的容器或画布）
    bg_sels = (
        bg_selector.split(",")
        if bg_selector
        else [
            ".geetest_canvas_bg",
            ".geetest_canvas_fullbg",
            "canvas.geetest_canvas_bg",
            "canvas",
            '[class*="canvas"]',
            '[class*="slider"] img',
            '[class*="verify"] canvas',
            '[class*="verify"] img',
        ]
    )

    for attempt in range(3):
        try:
            # 1. 定位滑块元素
            slider_elem = None
            for sel in slider_sels:
                slider_elem = page.query_selector(sel)
                if slider_elem and slider_elem.is_visible():
                    break

            if not slider_elem:
                continue

            slider_box = slider_elem.bounding_box()
            if not slider_box:
                continue

            # 2. 获取背景图
            bg_elem = None
            for sel in bg_sels:
                bg_elem = page.query_selector(sel)
                if bg_elem and bg_elem.is_visible():
                    break

            if bg_elem:
                bg_img = bg_elem.screenshot()
            else:
                bg_img = page.screenshot(full_page=False)

            # 3. 滑块图截图
            slider_img = slider_elem.screenshot()

            # 4. 计算缺口位置
            result = slide_match(slider_img, bg_img)
            target_x = result.get("target_x", 0)

            if target_x < 10:
                # 图像差分备选
                result2 = slide_comparison(bg_img, bg_img)
                target_x = result2.get("target_x", 0) if isinstance(result2, dict) else 0

            if target_x < 10:
                continue

            # 5. 生成轨迹
            # 实际滑动距离 = 目标位置 - 滑块初始位置 + 随机偏移
            distance = target_x - random.randint(0, 3)
            track = generate_track(distance, with_time=True, overshoot=True)

            # 6. 执行拖拽
            start_x = slider_box["x"] + slider_box["width"] / 2
            start_y = slider_box["y"] + slider_box["height"] / 2

            page.mouse.move(start_x, start_y)
            page.mouse.down()
            for x, y, dt in track:
                page.mouse.move(start_x + x, start_y + y, steps=1)
                page.wait_for_timeout(dt)
            page.mouse.up()

            # 7. 等待验证结果
            page.wait_for_timeout(1500)
            try:
                page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass

            # 检查滑块是否消失
            if not slider_elem.is_visible() or not slider_elem.is_attached():
                return {"success": True, "target_x": target_x, "attempts": attempt + 1}

            # 刷新重试（有些站允许重试）
            page.wait_for_timeout(random.randint(500, 1500))

        except Exception:
            continue

    return {"success": False, "target_x": 0, "attempts": 3}


def auto_solve_captcha(page):
    """page_action 回调：自动检测并解决验证码。

    用法:
      StealthyFetcher.fetch(url, page_action=auto_solve_captcha, ...)

    返回: dict 包含检测和解决结果
    """
    import sys

    info = detect_captcha_on_page(page)
    if not info:
        return {"captcha_detected": False}

    ctype = info["type"]
    print(f"[captcha_bypass] 检测到 {ctype} 验证码，尝试自动解决...", file=sys.stderr)

    if ctype == "image":
        text = solve_image_captcha_on_page(page, info.get("selector"))
        if text:
            print(f"[captcha_bypass] OCR 识别结果: {text}", file=sys.stderr)
            return {"captcha_detected": True, "type": "image", "solved": True, "text": text}
        else:
            print("[captcha_bypass] 图像验证码解决失败", file=sys.stderr)
            return {"captcha_detected": True, "type": "image", "solved": False}

    if ctype == "slider":
        result = solve_slider_captcha_on_page(page, info.get("selector"))
        if result["success"]:
            print(f"[captcha_bypass] 滑块验证成功 (attempt {result['attempts']})", file=sys.stderr)
            return {"captcha_detected": True, "type": "slider", "solved": True, "result": result}
        else:
            print("[captcha_bypass] 滑块验证失败", file=sys.stderr)
            return {"captcha_detected": True, "type": "slider", "solved": False}

    return {"captcha_detected": True, "type": ctype, "solved": False}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    cmd = sys.argv[1]

    try:
        if cmd == "ocr":
            image = sys.argv[2]
            beta = "--beta" in sys.argv
            png_fix = "--png-fix" in sys.argv
            if "--vision-fallback" in sys.argv:
                text, source = ocr_with_fallback(image, beta=beta, png_fix=png_fix)
                print(json.dumps({"text": text, "source": source}, ensure_ascii=False))
            else:
                result = ocr(image, beta=beta, png_fix=png_fix)
                print(result)

        elif cmd == "slide-match":
            target = sys.argv[2]
            background = sys.argv[3]
            simple = "--simple" in sys.argv
            result = slide_match(target, background, simple_target=simple)
            print(json.dumps(result))

        elif cmd == "slide-compare":
            target = sys.argv[2]
            background = sys.argv[3]
            result = slide_comparison(target, background)
            print(json.dumps(result))

        elif cmd == "track":
            distance = int(sys.argv[2])
            no_time = "--no-time" in sys.argv
            result = generate_track(distance, with_time=not no_time)
            print(json.dumps(list(result)))

        elif cmd == "detect":
            image = sys.argv[2]
            result = detect(image)
            print(json.dumps(result))

        elif cmd == "test":
            _run_self_test()

        else:
            print(f"未知命令: {cmd}", file=sys.stderr)
            print(__doc__)
            sys.exit(1)

    except IndexError:
        print("缺少参数。用法见文档:", file=sys.stderr)
        print(__doc__)
        sys.exit(1)
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)


def _run_self_test():
    """自检：验证 OCR 和滑块 API 可正常初始化。"""
    print("ddddocr 自检中...")
    _, DdddOcr = _get_ddddocr()

    # OCR 模型加载
    t0 = time.time()
    _ocr = DdddOcr(det=False, ocr=True)
    print(f"  OCR 模型加载: {time.time() - t0:.1f}s")

    # 滑块模型加载（验证实例化不会报错）
    t0 = time.time()
    _slide = DdddOcr(det=False, ocr=False)
    print(f"  滑块模型加载: {time.time() - t0:.1f}s")
    del _ocr, _slide

    # 轨迹生成测试
    track = generate_track(200, with_time=True)
    print(f"  轨迹生成: distance=200, steps={len(track)}")

    print("自检通过。ddddocr 可正常使用。")


if __name__ == "__main__":
    _main()
