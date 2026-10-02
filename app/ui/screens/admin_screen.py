from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.services.adversary import AdversaryClass, extract_features, is_probably_test
from app.services.benchmark import run_benchmark
from app.ui.theme.colors import ORANGE
from app.ui.widgets.header import Header
from app.ui.widgets.stat_card import PollRegisterPanel


class AdminScreen(QWidget):
    def __init__(self, window):
        super().__init__()
        self.window = window

        outer = QVBoxLayout()
        outer.setContentsMargins(36, 0, 36, 36)
        outer.setSpacing(16)

        outer.addWidget(Header("ADMIN / TESTER PANEL", "Ctrl+Shift+A to close"))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(20)

        self.register_panel = PollRegisterPanel()
        layout.addWidget(self.register_panel)

        layout.addWidget(self._section("Challenge and Spoil"))
        challenge_row = QHBoxLayout()
        self.challenge_button = QPushButton("CHALLENGE LAST BALLOT")
        self.challenge_button.setProperty("class", "danger")
        self.challenge_button.clicked.connect(self.challenge_last_ballot)
        challenge_row.addWidget(self.challenge_button)
        layout.addLayout(challenge_row)

        self.challenge_output = QTextEdit()
        self.challenge_output.setReadOnly(True)
        self.challenge_output.setFixedHeight(180)
        layout.addWidget(self.challenge_output)

        layout.addWidget(self._section("Attack Hooks (admin only)"))
        self.redirect_toggle = QCheckBox("Enable vote redirection")
        self.stuffing_toggle = QCheckBox("Enable ballot stuffing")
        self.malformed_toggle = QCheckBox("Enable malformed ballot injection (P2)")
        self.tally_toggle = QCheckBox("Enable tally manipulation (D verifier)")
        self.retroactive_edit_toggle = QCheckBox("Enable retroactive board edit (signature fail)")
        self.malformed_variant = QComboBox()
        self.malformed_variant.addItem("Outside range", "outside_range")
        self.malformed_variant.addItem("Two ones", "two_ones")
        self.malformed_variant.addItem("Non-canonical x + p", "non_canonical")
        self.redirect_index = QSpinBox()
        self.redirect_index.setMinimum(0)
        self.redirect_index.setMaximum(20)
        self.stuffed_count = QSpinBox()
        self.stuffed_count.setMinimum(1)
        self.stuffed_count.setMaximum(50)
        self.stuffed_count.setValue(3)
        layout.addWidget(self.redirect_toggle)
        layout.addWidget(self.redirect_index)
        layout.addWidget(self.stuffing_toggle)
        layout.addWidget(self.stuffed_count)
        layout.addWidget(self.malformed_toggle)
        layout.addWidget(self.malformed_variant)
        layout.addWidget(self.tally_toggle)
        layout.addWidget(self.retroactive_edit_toggle)

        layout.addWidget(self._section("Adversary Simulation"))
        self.adversary_select = QComboBox()
        for adversary in AdversaryClass:
            self.adversary_select.addItem(adversary.value, adversary)
        self.adversary_result = QLabel("is_probably_test: —")
        self.adversary_result.setStyleSheet("font-size: 24px; font-weight: 700;")
        layout.addWidget(self.adversary_select)
        layout.addWidget(self.adversary_result)

        layout.addWidget(self._section("Hardware Benchmark"))
        benchmark_row = QHBoxLayout()
        self.benchmark_button = QPushButton("RUN 500 BALLOTS")
        self.benchmark_button.clicked.connect(self.run_benchmark)
        self.benchmark_progress = QProgressBar()
        self.benchmark_progress.setRange(0, 500)
        benchmark_row.addWidget(self.benchmark_button)
        benchmark_row.addWidget(self.benchmark_progress, stretch=1)
        layout.addLayout(benchmark_row)

        self.benchmark_output = QTextEdit()
        self.benchmark_output.setReadOnly(True)
        self.benchmark_output.setFixedHeight(220)
        layout.addWidget(self.benchmark_output)
                # ------ Election Lifecycle (produce bulletin board from GUI) ----
        layout.addWidget(self._section("Election Lifecycle"))

        self.close_poll_button = QPushButton("CLOSE POLL")
        self.close_poll_button.setProperty("class", "danger")
        self.close_poll_button.clicked.connect(self.close_poll)
        layout.addWidget(self.close_poll_button)

        self.tally_button = QPushButton("COMPUTE TALLY")
        self.tally_button.clicked.connect(self.compute_tally)
        self.tally_button.setEnabled(False)
        layout.addWidget(self.tally_button)

        self.export_button = QPushButton("SIGN AND EXPORT BOARD")
        self.export_button.clicked.connect(self.export_board)
        self.export_button.setEnabled(False)
        layout.addWidget(self.export_button)

        layout.addWidget(QLabel("Bundle tag (e.g. 'clean', 'redirection', 'malformed'):"))
        self.bundle_tag_input = QLineEdit()
        self.bundle_tag_input.setPlaceholderText("clean")
        self.bundle_tag_input.setText("clean")
        layout.addWidget(self.bundle_tag_input)

        self.bundle_button = QPushButton("EXPORT BUNDLE")
        self.bundle_button.clicked.connect(self.export_bundle)
        self.bundle_button.setEnabled(False)
        layout.addWidget(self.bundle_button)

        self.lifecycle_output = QTextEdit()
        self.lifecycle_output.setReadOnly(True)
        self.lifecycle_output.setFixedHeight(220)
        layout.addWidget(self.lifecycle_output)
        close = QPushButton("CLOSE ADMIN PANEL")
        close.setProperty("class", "secondary")
        close.clicked.connect(window.hide_admin)
        layout.addWidget(close)

        body.setLayout(layout)
        scroll.setWidget(body)
        outer.addWidget(scroll)
        self.setLayout(outer)

    def refresh(self) -> None:
        poll = self.window.poll_state
        register = poll.poll_register()
        self.register_panel.update_counts(
            register["ballots_issued"],
            register["ballots_spoiled"],
            register["ballots_counted"],
        )

        service = self.window.ballot_service
        service.attack_config.vote_redirection_enabled = self.redirect_toggle.isChecked()
        service.attack_config.ballot_stuffing_enabled = self.stuffing_toggle.isChecked()
        service.attack_config.malformed_ballot_enabled = self.malformed_toggle.isChecked()
        service.attack_config.malformed_ballot_variant = self.malformed_variant.currentData() or "outside_range"
        service.attack_config.tally_manipulation_enabled = self.tally_toggle.isChecked()
        service.attack_config.retroactive_board_edit_enabled = self.retroactive_edit_toggle.isChecked()
        service.attack_config.redirect_to_index = self.redirect_index.value()
        service.attack_config.stuffed_count = self.stuffed_count.value()

        session = poll.current_ballot or (
            poll.sessions[-1] if poll.sessions else None
        )
        features = extract_features(poll, session)
        adversary = self.adversary_select.currentData()
        guess = is_probably_test(features, adversary)
        self.adversary_result.setText(
            "is_probably_test: TRUE"
            if guess
            else "is_probably_test: FALSE"
        )

        self.redirect_index.setMaximum(max(0, self.window.config.candidate_count - 1))

    def challenge_last_ballot(self) -> None:
        service = self.window.ballot_service
        artifacts = service.last_artifacts
        if artifacts is None:
            self.challenge_output.setPlainText("No ballot available to challenge.")
            return

        if artifacts.serial not in self.window.testing_authority.schedule:
            # SPEC 10.2: only scheduled serials are challenged. A spoil on any
            # other serial is a P3 failure on the board.
            self.challenge_output.setPlainText(
                f"Serial {artifacts.serial} is not a scheduled test ballot; "
                "challenge refused (SPEC 10.2).")
            return

        service.append_spoil(artifacts, artifacts.candidate_index)
        self.window.poll_state.spoil_current_ballot()
        spoil = service.board["spoils"][-1]
        reencrypts = service.verify_spoil_record(spoil)

        lines = [
            f"Ballot serial: {artifacts.serial}",
            f"Opened candidate index: {artifacts.candidate_index}",
            f"Commitment nonce: {artifacts.nonce}",
            "Randomness vector:",
            *artifacts.randomness,
            "",
            "Re-encryption check (SPEC 11): "
            + ("all published ciphertext components match."
               if reencrypts else "MISMATCH, this record would be rejected."),
        ]
        self.challenge_output.setPlainText("\n".join(lines))
        self.refresh()

    def run_benchmark(self) -> None:
        self.benchmark_progress.setValue(0)
        result = run_benchmark(
            self.window.config,
            self.window.ballot_service,
            ballot_count=500,
        )
        self.benchmark_progress.setValue(500)

        def stats(values):
            ordered = sorted(values)
            return (f"{ordered[0]:.0f} / {ordered[len(ordered) // 2]:.0f} / "
                    f"{ordered[-1]:.0f}")

        self.benchmark_output.setPlainText(
            "\n".join(
                [
                    f"Candidates (m): {result.candidate_count}",
                    f"Ballots run: {result.ballot_count}",
                    "                     min / median / max (ms)",
                    f"encrypt_and_prove    {stats(result.encrypt_prove_times_ms)}",
                    f"record and board     {stats(result.record_times_ms)}",
                    f"cast latency         {stats(result.cast_times_ms)}",
                    f"Peak RSS (process): {result.peak_memory_mb:.1f} MB",
                    "",
                    "Paper figures: python -m harness.bench (percentiles per m).",
                ]
            )
        )
        self.refresh()

        # ------------------------------------------------------------------
    # Election lifecycle: close, tally, sign and export from the GUI
    # ------------------------------------------------------------------

    def close_poll(self) -> None:
        """Publish the testing authority's schedule seed and write the poll
        register to the in-memory board. The pre-poll section was published
        when the kiosk started. After this, the board has everything except
        the tally and signatures."""
        svc = self.window.ballot_service
        try:
            svc.reveal_schedule_and_publish_register(self.window.testing_authority.reveal())
            reg = self.window.poll_state.poll_register()
            self.lifecycle_output.setPlainText(
                f"Poll closed.\n"
                f"  ballots_issued  = {reg['ballots_issued']}\n"
                f"  ballots_spoiled = {reg['ballots_spoiled']}\n"
                f"  ballots_counted = {reg['ballots_counted']}\n\n"
                f"Now click COMPUTE TALLY."
            )
            self.close_poll_button.setEnabled(False)
            self.tally_button.setEnabled(True)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Close Poll Failed", str(exc))

    def compute_tally(self) -> None:
        """Aggregate ciphertexts per candidate, threshold-decrypt,
        recover the per-candidate vote counts, and write the tally
        sections to the board. Fires the tally-manipulation hook here if
        that attack toggle is on."""
        import random
        from tally.threshold import (
            aggregate_ciphertexts, threshold_decrypt,
            build_decryption_transcript,
        )
        from tally.trustees import choose_decryption_subset
        from crypto.elgamal import recover_exponent
        from crypto.record import hex384
        from board import board as bb

        svc = self.window.ballot_service
        cfg = self.window.config
        reg = self.window.poll_state.poll_register()

        try:
            subset = choose_decryption_subset(svc.trustee_setup)
            columns = svc.valid_ballots_ciphertexts()
            aggregates = []
            tally = {}
            partials = []
            lagrange = {}
            proof_rng = random.Random(cfg.seed ^ 0xBEEFCAFE)

            for i, column in enumerate(columns):
                if not column:
                    A_i, B_i = 1, 1
                    aggregates.append({
                        "candidate_index": i,
                        "alpha": hex384(A_i), "beta": hex384(B_i),
                    })
                    tally[i] = 0
                    continue
                A_i, B_i = aggregate_ciphertexts(column)
                aggregates.append({
                    "candidate_index": i,
                    "alpha": hex384(A_i), "beta": hex384(B_i),
                })
                g_to_T = threshold_decrypt(
                    (A_i, B_i), svc.trustee_setup.shares, subset,
                )
                tally[i] = recover_exponent(
                    g_to_T, max(1, reg["ballots_counted"]),
                )
                pc = build_decryption_transcript(
                    trustee_shares=svc.trustee_setup.shares,
                    trustee_commitments=svc.trustee_setup.commitments,
                    subset=subset, candidate_index=i,
                    aggregate_ciphertext=(A_i, B_i),
                    Q=svc.Q, rng=proof_rng,
                )
                lagrange.update(pc["lagrange_coefficients"])
                partials.extend(pc["partials"])

            svc.board["tally_aggregate"] = {
                "record_type": "tally_aggregate", "columns": aggregates,
            }
            bb.append_decryption_transcript(
                svc.board, subset=sorted(subset),
                lagrange_coefficients=lagrange, partials=partials,
            )
            svc.board["tally_declaration"] = {
                "record_type": "tally_declaration",
                "totals": [
                    {"candidate_index": c.index,
                     "candidate_id": c.candidate_id,
                     "votes": tally.get(c.index, 0)}
                    for c in cfg.candidates
                ],
            }

            # Tally-manipulation hook ---------------------------------
            if svc.attack_config.tally_manipulation_enabled:
                svc.board["tally_declaration"]["totals"][0]["votes"] += 100
                c10_note = "\n\n!! Tally-manipulation attack active: CAND-A tally +100"
            else:
                c10_note = ""

            lines = ["Per-candidate tally:"]
            for c in cfg.candidates:
                votes = svc.board["tally_declaration"]["totals"][c.index]["votes"]
                lines.append(f"  {c.candidate_id}: {votes}")
            lines.append(
                f"\nsum = {sum(r['votes'] for r in svc.board['tally_declaration']['totals'])} "
                f"(register counted = {reg['ballots_counted']})"
            )
            lines.append(c10_note if c10_note else "")
            lines.append("\nNow click SIGN AND EXPORT BOARD.")
            self.lifecycle_output.setPlainText("\n".join(lines))
            self.tally_button.setEnabled(False)
            self.export_button.setEnabled(True)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Compute Tally Failed", str(exc))

    def export_board(self) -> None:
        """Compute digest, produce officer + agent multisignature,
        write board.json and signatures.json to disk. Fires the retroactive-edit hook
        (retroactive board edit) here if that attack toggle is on."""
        from pathlib import Path
        from board import board as bb
        from board.digest import compute_board_digest
        from board.signature import (
            create_signature_message, sign_message,
            create_signature_file, write_signature_file,
        )
        from board.export import export_files

        svc = self.window.ballot_service
        try:
            out = Path("out")
            out.mkdir(exist_ok=True)
            board_path = out / "board.json"
            sig_path = out / "signatures.json"

            bb.write_board(svc.board, str(board_path))
            digest = compute_board_digest(svc.board)
            msg = create_signature_message(digest)
            officer_sig = sign_message(
                svc._authority_privates["officer"], msg,
            )
            agent_sigs = [
                sign_message(priv, msg)
                for priv in svc._authority_privates["agents"]
            ]
            sigfile = create_signature_file(
                digest, officer_sig, agent_sigs,
            )
            write_signature_file(sigfile, str(sig_path))

            # Retroactive-edit hook -----------------------------------
            if svc.attack_config.retroactive_board_edit_enabled:
                if svc.board["ballots"]:
                    b0 = svc.board["ballots"][0]
                    a = b0["ciphertexts"][0]["alpha"]
                    b0["ciphertexts"][0]["alpha"] = (
                        ("f" if a[0] != "f" else "0") + a[1:]
                    )
                    bb.write_board(svc.board, str(board_path))
                    c11_note = "\n!! Retroactive-edit attack active: ballot 1 mutated after signing"
                else:
                    c11_note = ""
            else:
                c11_note = ""

            export_files(str(board_path), str(sig_path))
            self.lifecycle_output.setPlainText(
                f"Board signed and exported.\n"
                f"  digest    : {digest}\n"
                f"  board     : {board_path.resolve()}\n"
                f"  signatures: {sig_path.resolve()}"
                f"{c11_note}\n\n"
                f"Now set a bundle tag and click EXPORT BUNDLE."
            )
            self.export_button.setEnabled(False)
            self.bundle_button.setEnabled(True)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Export Failed", str(exc))

    def export_bundle(self) -> None:
        """Package board.json + signatures.json + election.json into
        bundle-<tag>/ and a tar.gz for the verifier."""
        import shutil
        import tarfile
        from pathlib import Path
        from board.export import scan_for_secrets
        import json

        try:
            tag = self.bundle_tag_input.text().strip() or "run"
            # Sanitise tag to be filesystem-safe.
            tag_safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in tag)

            out = Path("out")
            board_p = out / "board.json"
            sig_p = out / "signatures.json"
            cfg_p = Path("config") / "election.json"
            if not all(p.exists() for p in (board_p, sig_p, cfg_p)):
                raise RuntimeError(
                    "board.json, signatures.json, or config/election.json "
                    "missing. Did you click SIGN AND EXPORT BOARD?"
                )

            board_data = json.loads(board_p.read_text(encoding="utf-8"))
            findings = scan_for_secrets(board_data)
            if findings:
                raise RuntimeError(
                    f"Secrets scan found forbidden fields: {findings}. "
                    "Refusing to bundle."
                )

            bundle_dir_name = f"bundle-{tag_safe}"
            bundle_dir = Path(bundle_dir_name)
            if bundle_dir.exists():
                shutil.rmtree(bundle_dir)
            bundle_dir.mkdir()
            shutil.copy2(board_p, bundle_dir / "board.json")
            shutil.copy2(sig_p, bundle_dir / "signatures.json")
            shutil.copy2(cfg_p, bundle_dir / "election.json")

            tar_path = Path(f"{bundle_dir_name}.tar.gz")
            if tar_path.exists():
                tar_path.unlink()
            with tarfile.open(tar_path, "w:gz") as tar:
                tar.add(bundle_dir, arcname=bundle_dir.name)

            self.lifecycle_output.setPlainText(
                f"Bundle ready.\n"
                f"  folder: {bundle_dir.resolve()}\n"
                f"  tar.gz: {tar_path.resolve()} "
                f"({tar_path.stat().st_size} bytes)\n\n"
                f"To generate another scenario, relaunch the app "
                f"and set a new bundle tag."
            )
            self.bundle_button.setEnabled(False)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Bundle Failed", str(exc))
    @staticmethod
    def _section(title: str) -> QFrame:
        frame = QFrame()
        label = QLabel(title)
        label.setStyleSheet(
            f"font-size: 28px; font-weight: 700; color: {ORANGE}; padding-top: 8px;"
        )
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(label)
        frame.setLayout(layout)
        return frame
