from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout

from app.ui.theme.colors import LIGHT_BLUE, ORANGE, WHITE


class Header(QFrame):
    def __init__(self, title: str = "E2E-V-IND-EVM", subtitle: str = ""):
        super().__init__()
        self.setFixedHeight(140)
        self.setStyleSheet(
            f"""
            QFrame {{
                background: {ORANGE};
                border: none;
                border-bottom: 4px solid {LIGHT_BLUE};
            }}
            QLabel {{
                color: {WHITE};
                background: transparent;
            }}
            """
        )

        layout = QVBoxLayout()
        layout.setContentsMargins(36, 18, 36, 18)
        layout.setSpacing(4)

        heading = QLabel(title)
        heading.setStyleSheet("font-size: 34px; font-weight: 700;")
        layout.addWidget(heading)

        if subtitle:
            sub = QLabel(subtitle)
            sub.setStyleSheet("font-size: 22px; font-weight: 500;")
            layout.addWidget(sub)

        self.setLayout(layout)


class StatusBar(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("statusBar")

        root = QHBoxLayout()
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(16)

        self.serial_value, self._serial_frame = self._metric("Ballot", "—")
        self.booth_value, self._booth_frame = self._metric("Booth", "—")
        self.register_value, self._register_frame = self._metric("Counted", "0")

        for frame in (self._serial_frame, self._booth_frame, self._register_frame):
            root.addWidget(frame, stretch=1)

        self.setLayout(root)

    def _metric(self, caption: str, value: str) -> tuple[QLabel, QFrame]:
        frame = QFrame()
        frame.setObjectName("metricCell")
        frame.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Fixed,
        )
        frame.setMinimumHeight(88)

        layout = QVBoxLayout()
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)

        cap = QLabel(caption)
        cap.setStyleSheet("font-size: 18px; color: #5A6B75;")

        val = QLabel(value)
        val.setStyleSheet("font-size: 26px; font-weight: 700;")
        val.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        layout.addWidget(cap)
        layout.addWidget(val)
        frame.setLayout(layout)
        return val, frame

    def set_serial(self, serial: "int | None") -> None:
        self.serial_value.setText(str(serial) if serial else "—")

    def set_booth(self, booth_id: str) -> None:
        self.booth_value.setText(booth_id)

    def set_counted(self, counted: int, issued: int) -> None:
        self.register_value.setText(f"{counted} / {issued}")
