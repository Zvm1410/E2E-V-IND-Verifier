from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget

from app.ui.widgets.logo import party_logo_pixmap


class LogoScreen(QWidget):
    def __init__(self, window):
        super().__init__()
        self.window = window
        self.timer = QTimer()
        self.timer.timeout.connect(self._tick)
        self.remaining = 0

        root = QVBoxLayout()
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.logo_label = QLabel()
        self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # small bilingual caption (English / Hindi) below the logo
        self.caption = QLabel("")
        self.caption.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.caption.setProperty("class", "subtitle")

        # visible countdown timer label
        self.countdown_label = QLabel("")
        self.countdown_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.countdown_label.setStyleSheet("font-size: 20px; color: #5A6B75;")

        root.addStretch()
        root.addWidget(self.logo_label, alignment=Qt.AlignmentFlag.AlignHCenter)
        root.addWidget(self.caption, alignment=Qt.AlignmentFlag.AlignHCenter)
        root.addWidget(self.countdown_label, alignment=Qt.AlignmentFlag.AlignHCenter)
        root.addStretch()

        self.setLayout(root)

    def show_logo(self, candidate_index: int, seconds: int = 4) -> None:
        # choose size based on the window to keep the logo square and not stretched
        try:
            w = self.window.width()
            h = self.window.height()
        except Exception:
            w, h = 800, 600

        # make logo roughly 40% of the smaller window dimension, clamp to sensible bounds
        pix_size = int(max(200, min(w, h) * 0.4))
        pix = party_logo_pixmap(candidate_index, pix_size)

        # fix the label to the pixmap size so the image is not stretched
        self.logo_label.setFixedSize(pix_size, pix_size)
        self.logo_label.setPixmap(pix)
        self.logo_label.setScaledContents(False)

        # bilingual caption: keep it subtle but present
        self.caption.setText("Vote Recorded — मत दर्ज हुआ")

        # start countdown (1s ticks) and set remaining seconds
        self.remaining = int(seconds)
        self._update_countdown_text()
        self.timer.start(1000)

    def _tick(self) -> None:
        self.remaining -= 1
        if self.remaining <= 0:
            self.finish()
        else:
            self._update_countdown_text()

    def _update_countdown_text(self) -> None:
        # bilingual countdown: English + Hindi
        self.countdown_label.setText(f"Returning to start in {self.remaining} seconds — {self.remaining} सेकंड में शुरू")

    def finish(self) -> None:
        self.timer.stop()
        self.window.finish_voting_cycle()

    def refresh_status(self) -> None:
        # no-op; logo screen doesn't use status
        return
