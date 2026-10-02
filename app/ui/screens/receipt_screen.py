from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtWidgets import QFrame, QLabel, QPushButton, QVBoxLayout, QWidget

from app.ui.theme.colors import GREEN, LIGHT_BLUE
from app.ui.widgets.header import Header, StatusBar


class ReceiptScreen(QWidget):
    def __init__(self, window):
        super().__init__()
        self.window = window
        self.remaining = 12
        self.timer = QTimer()
        self.timer.timeout.connect(self.tick)

        root = QVBoxLayout()
        root.setContentsMargins(48, 0, 48, 48)
        root.setSpacing(24)

        self.header = Header("VOTE RECORDED")
        self.status = StatusBar()

        message = QLabel("Your ballot has been encrypted and submitted.")
        message.setProperty("class", "subtitle")
        message.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card = QFrame()
        card.setProperty("class", "card")
        card_layout = QVBoxLayout()
        card_layout.setContentsMargins(36, 36, 36, 36)
        card_layout.setSpacing(16)

        serial_caption = QLabel("Ballot Serial")
        serial_caption.setProperty("class", "hint")
        serial_caption.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.serial_label = QLabel("—")
        self.serial_label.setStyleSheet("font-size: 52px; font-weight: 700;")
        self.serial_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        receipt_caption = QLabel("Receipt Code")
        receipt_caption.setProperty("class", "hint")
        receipt_caption.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.receipt_label = QLabel("—")
        self.receipt_label.setProperty("class", "receipt-code")
        self.receipt_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.countdown_label = QLabel("")
        self.countdown_label.setStyleSheet(
            f"font-size: 22px; color: #5A6B75; background: {LIGHT_BLUE}; "
            "border-radius: 12px; padding: 16px;"
        )
        self.countdown_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card_layout.addWidget(serial_caption)
        card_layout.addWidget(self.serial_label)
        card_layout.addWidget(receipt_caption)
        card_layout.addWidget(self.receipt_label)
        card_layout.addWidget(self.countdown_label)
        card.setLayout(card_layout)

        done = QPushButton("FINISH")
        done.setFixedHeight(88)
        done.clicked.connect(self.finish)

        root.addWidget(self.header)
        root.addWidget(self.status)
        root.addStretch()
        root.addWidget(message)
        root.addWidget(card)
        root.addStretch()
        root.addWidget(done)
        self.setLayout(root)

    def show_receipt(self, serial: int, receipt_code: str) -> None:
        self.serial_label.setText(str(serial))
        self.receipt_label.setText(receipt_code)
        self.remaining = 12
        self.update_text()
        self.timer.start(1000)

    def tick(self) -> None:
        self.remaining -= 1
        self.update_text()
        if self.remaining <= 0:
            self.finish()

    def update_text(self) -> None:
        self.countdown_label.setText(
            f"Returning to start in {self.remaining} seconds"
        )

    def finish(self) -> None:
        self.timer.stop()
        self.window.finish_voting_cycle()

    def refresh_status(self) -> None:
        poll = self.window.poll_state
        register = poll.poll_register()
        self.status.set_booth(self.window.config.booth_id)
        self.status.set_serial(None)
        self.status.set_counted(register["ballots_counted"], register["ballots_issued"])
