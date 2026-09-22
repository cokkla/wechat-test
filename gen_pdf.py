# pip install reportlab
import os

from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfgen import canvas

OUTPUT_PATH = os.path.join("files", "test_25mb.pdf")

POEM_LINE = "床前明月光，疑是地上霜。举头望明月，低头思故乡。"

pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))

os.makedirs("files", exist_ok=True)

c = canvas.Canvas(OUTPUT_PATH)
# 重复写入大量内容直到接近 25MB（showPage 会重置字体，每页都要重新设置）
for i in range(42000):
    c.setFont("STSong-Light", 12)
    c.drawString(72, 720, "静夜思 - 李白")
    c.drawString(72, 700, f"第{i}行 " + POEM_LINE)
    c.showPage()
c.save()

print("实际大小:", os.path.getsize(OUTPUT_PATH))