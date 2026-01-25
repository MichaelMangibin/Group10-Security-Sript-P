import tkinter as tk
from tkinter import ttk, messagebox

from password_tools import (
    generate_password,
    hash_password_sha256,
    save_password_entry,
    check_password_strength,
    get_timestamp,
)
from form_tools import (
    sanitize_text_basic,
    remove_prohibited_patterns,
    validate_full_name,
    validate_email,
    validate_username,
    validate_message,
)

# Matrix + Neo Green Theme colors
THEME = {
    "bg": "#050a07",          # almost black with green tint
    "panel": "#07130d",       # dark green panel
    "text": "#b6ffcf",        # mint/neon text
    "muted": "#6adf95",       # muted green
    "accent": "#00ff66",      # neon green (main accent)
    "accent2": "#00cc55",     # darker neon (selection/active)
    "border": "#0f3d25",      # green border
    "entry_bg": "#03110a",    # very dark green for inputs/text areas
    "button": "#062016",      # button base
    "button_hover": "#0a2e1f" # hover
}


class MultiFunctionWebSecurityToolApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Multi-Function Web Security Tool")
        self.geometry("900x700")
        self.minsize(800, 550)
        self.resizable(True, True)

        self.apply_theme()
        self._build_ui()

    # Theme / Styling
    def apply_theme(self):
        # Window background
        self.configure(bg=THEME["bg"])

        style = ttk.Style(self)
        style.theme_use("clam")  # best for custom colors

        # Notebook + tabs
        style.configure("TNotebook", background=THEME["bg"], borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=THEME["button"],
            foreground=THEME["text"],
            padding=(12, 6),
        )
        style.map(
            "TNotebook.Tab",
            background=[
                ("selected", THEME["panel"]),
                ("active", THEME["button_hover"]),
            ],
            foreground=[
                ("selected", THEME["accent"]),
                ("active", THEME["accent"]),
            ],
        )

        # Frames / Labelframes
        style.configure("TFrame", background=THEME["bg"])
        style.configure("TLabelframe", background=THEME["bg"], foreground=THEME["text"])
        style.configure("TLabelframe.Label", background=THEME["bg"], foreground=THEME["accent"])

        # Labels
        style.configure("TLabel", background=THEME["bg"], foreground=THEME["text"])

        # Buttons
        style.configure(
            "TButton",
            background=THEME["button"],
            foreground=THEME["text"],
            padding=(10, 6),
            borderwidth=1,
            relief="flat",
        )
        style.map(
            "TButton",
            background=[("active", THEME["button_hover"])],
            foreground=[("active", THEME["accent"])],
        )

        # Entry fields
        style.configure(
            "TEntry",
            fieldbackground=THEME["entry_bg"],
            foreground=THEME["text"],
            insertcolor=THEME["accent"],
        )

    def _style_text_widget(self, widget: tk.Text):
        # ttk styles do NOT affect tk.Text, so we style it manually
        widget.configure(
            bg=THEME["entry_bg"],
            fg=THEME["text"],
            insertbackground=THEME["accent"],   # cursor neon green
            selectbackground=THEME["accent2"],
            highlightbackground=THEME["border"],
            highlightcolor=THEME["accent"],
            relief="flat",
            bd=1,
        )

    # Shared Output Helpers
    @staticmethod
    def _clear_text(widget: tk.Text):
        widget.config(state="normal")
        widget.delete("1.0", tk.END)
        widget.config(state="disabled")

    @staticmethod
    def _write_line(widget: tk.Text, line: str):
        widget.config(state="normal")
        widget.insert(tk.END, line + "\n")
        widget.config(state="disabled")

    # UI Section
    def _build_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_strength = ttk.Frame(notebook)
        self.tab_generator = ttk.Frame(notebook)
        self.tab_form = ttk.Frame(notebook)

        notebook.add(self.tab_strength, text="Password Strength")
        notebook.add(self.tab_generator, text="Generate + Hash + Save")
        notebook.add(self.tab_form, text="Web Form Validator")

        self._build_strength_tab()
        self._build_generator_tab()
        self._build_form_tab()

    # TAB 1: Password Strength
    def _build_strength_tab(self):
        frm = ttk.LabelFrame(self.tab_strength, text="Password Strength Assessment", padding=10)
        frm.pack(fill="x", padx=10, pady=10)

        ttk.Label(frm, text="Enter Password:").grid(row=0, column=0, sticky="w")
        self.strength_entry = ttk.Entry(frm, width=55)
        self.strength_entry.grid(row=0, column=1, padx=10, pady=5)

        ttk.Button(frm, text="Check Strength", command=self.on_check_strength).grid(row=0, column=2, padx=10)

        out_frame = ttk.LabelFrame(self.tab_strength, text="Output", padding=10)
        out_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.strength_output = tk.Text(out_frame, height=18, wrap="word")
        self.strength_output.pack(fill="both", expand=True)
        self._style_text_widget(self.strength_output)
        self.strength_output.config(state="disabled")

    def on_check_strength(self):
        pw = self.strength_entry.get()
        if not pw:
            messagebox.showerror("Missing Input", "Please enter a password to check.")
            return

        rating, tips = check_password_strength(pw)

        self._clear_text(self.strength_output)
        self._write_line(self.strength_output, "Password Strength Assessment:")
        self._write_line(self.strength_output, f"- Strength: {rating}")
        if tips:
            self._write_line(self.strength_output, "Tips:")
            for t in tips:
                self._write_line(self.strength_output, f"  • {t}")

    # TAB 2: Generator + Hash + Save + Copy + Show/Hide
    def _build_generator_tab(self):
        frm = ttk.LabelFrame(self.tab_generator, text="Secure Password Generator + SHA-256 + Save", padding=10)
        frm.pack(fill="x", padx=10, pady=10)

        ttk.Button(frm, text="Generate Password", command=self.on_generate_password).grid(
            row=0, column=0, padx=10, pady=5
        )

        self.gen_timestamp_var = tk.StringVar(value="")
        self.gen_password_var = tk.StringVar(value="")
        self.gen_hash_var = tk.StringVar(value="")

        ttk.Label(frm, text="Timestamp:").grid(row=1, column=0, sticky="w")
        ttk.Label(frm, textvariable=self.gen_timestamp_var).grid(row=1, column=1, sticky="w", padx=10)

        ttk.Label(frm, text="Password:").grid(row=2, column=0, sticky="w")

        self.gen_password_entry = ttk.Entry(frm, textvariable=self.gen_password_var, width=40)
        self.gen_password_entry.grid(row=2, column=1, sticky="w", padx=10)

        self._password_hidden = True
        self.gen_password_entry.config(show="*")

        self.btn_show_hide = ttk.Button(frm, text="Show Password", command=self.on_toggle_show_hide)
        self.btn_show_hide.grid(row=2, column=2, padx=5)

        self.btn_copy = ttk.Button(frm, text="Copy Password", command=self.on_copy_password)
        self.btn_copy.grid(row=2, column=3, padx=5)

        ttk.Label(frm, text="Hash:").grid(row=3, column=0, sticky="w")
        ttk.Label(frm, textvariable=self.gen_hash_var, wraplength=720, justify="left").grid(
            row=3, column=1, columnspan=3, sticky="w", padx=10, pady=5
        )

        out_frame = ttk.LabelFrame(self.tab_generator, text="Output", padding=10)
        out_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.gen_output = tk.Text(out_frame, height=18, wrap="word")
        self.gen_output.pack(fill="both", expand=True)
        self._style_text_widget(self.gen_output)
        self.gen_output.config(state="disabled")

    def on_generate_password(self):
        password = generate_password()
        pw_hash = hash_password_sha256(password)
        timestamp = get_timestamp()

        self.gen_password_var.set(password)
        self.gen_hash_var.set(pw_hash)
        self.gen_timestamp_var.set(timestamp)

        try:
            save_password_entry(timestamp, password, pw_hash)
        except Exception as e:
            messagebox.showerror("File Error", f"Could not save to passwords.txt:\n{e}")
            return

        self._clear_text(self.gen_output)
        self._write_line(self.gen_output, "Secure Password Generation + Hashing:")
        self._write_line(self.gen_output, f"Timestamp: {timestamp}")
        self._write_line(self.gen_output, f"Password: {password}")
        self._write_line(self.gen_output, f"Hash: {pw_hash}")
        self._write_line(self.gen_output, "Saved to passwords.txt (append mode).")

    def on_copy_password(self):
        password = self.gen_password_var.get().strip()
        if not password:
            messagebox.showerror("Nothing to Copy", "Generate a password first.")
            return

        self.clipboard_clear()
        self.clipboard_append(password)
        self.update()
        messagebox.showinfo("Copied", "Password copied to clipboard.")

    def on_toggle_show_hide(self):
        if self._password_hidden:
            self.gen_password_entry.config(show="")
            self.btn_show_hide.config(text="Hide Password")
            self._password_hidden = False
        else:
            self.gen_password_entry.config(show="*")
            self.btn_show_hide.config(text="Show Password")
            self._password_hidden = True

    # TAB 3: Web Form Validator + Sanitizer
    def _build_form_tab(self):
        frm = ttk.LabelFrame(self.tab_form, text="Web Form Input Validator + Sanitizer", padding=10)
        frm.pack(fill="x", padx=10, pady=10)

        ttk.Label(frm, text="Full Name:").grid(row=0, column=0, sticky="w")
        self.full_name_entry = ttk.Entry(frm, width=55)
        self.full_name_entry.grid(row=0, column=1, padx=10, pady=5)

        ttk.Label(frm, text="Email Address:").grid(row=1, column=0, sticky="w")
        self.email_entry = ttk.Entry(frm, width=55)
        self.email_entry.grid(row=1, column=1, padx=10, pady=5)

        ttk.Label(frm, text="Username:").grid(row=2, column=0, sticky="w")
        self.username_entry = ttk.Entry(frm, width=55)
        self.username_entry.grid(row=2, column=1, padx=10, pady=5)

        ttk.Label(frm, text="Message / Comment:").grid(row=3, column=0, sticky="nw")
        self.message_text = tk.Text(frm, width=60, height=6, wrap="word")
        self.message_text.grid(row=3, column=1, padx=10, pady=5, sticky="w")
        self._style_text_widget(self.message_text)

        btn_row = ttk.Frame(frm)
        btn_row.grid(row=4, column=1, sticky="w", pady=5)

        ttk.Button(btn_row, text="Validate Form", command=self.on_validate_form).pack(side="left", padx=5)
        ttk.Button(btn_row, text="Reset Form", command=self.on_reset_form).pack(side="left", padx=5)

        out_frame = ttk.LabelFrame(self.tab_form, text="Output", padding=10)
        out_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.form_output = tk.Text(out_frame, height=18, wrap="word")
        self.form_output.pack(fill="both", expand=True)
        self._style_text_widget(self.form_output)
        self.form_output.config(state="disabled")

    def on_reset_form(self):
        self.full_name_entry.delete(0, tk.END)
        self.email_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.message_text.delete("1.0", tk.END)
        self._clear_text(self.form_output)

    def on_validate_form(self):
        full_name = self.full_name_entry.get()
        email = self.email_entry.get()
        username = self.username_entry.get()
        message = self.message_text.get("1.0", tk.END).rstrip("\n")

        if not full_name.strip() or not email.strip() or not username.strip() or not message.strip():
            messagebox.showerror("Missing Field", "All fields are required. Please fill in all fields.")
            return

        fn_clean, fn_notes = sanitize_text_basic(full_name)
        em_clean, em_notes = sanitize_text_basic(email)
        un_clean, un_notes = sanitize_text_basic(username)

        msg_clean, msg_notes1 = sanitize_text_basic(message)
        msg_clean, msg_notes2 = remove_prohibited_patterns(msg_clean)
        msg_notes = msg_notes1 + msg_notes2

        sanitize_notes = {
            "full_name": fn_notes,
            "email": em_notes,
            "username": un_notes,
            "message": msg_notes,
        }

        fn_ok, fn_errs = validate_full_name(fn_clean)
        em_ok, em_errs = validate_email(em_clean)
        un_ok, un_errs = validate_username(un_clean)
        msg_ok, msg_errs = validate_message(msg_clean)

        self._clear_text(self.form_output)
        self._write_line(self.form_output, "Validation Results:")

        if fn_ok:
            self._write_line(self.form_output, "- Full Name: Valid")
        else:
            self._write_line(self.form_output, f"- Full Name: Invalid ({fn_errs[0]})")
            for e in fn_errs:
                self._write_line(self.form_output, f"  * {e}")

        if em_ok:
            self._write_line(self.form_output, "- Email: Valid")
        else:
            self._write_line(self.form_output, f"- Email: Invalid ({em_errs[0]})")
            for e in em_errs:
                self._write_line(self.form_output, f"  * {e}")

        if un_ok:
            self._write_line(self.form_output, "- Username: Valid")
        else:
            self._write_line(self.form_output, f"- Username: Invalid ({un_errs[0]})")
            for e in un_errs:
                self._write_line(self.form_output, f"  * {e}")

        if msg_ok:
            if msg_notes:
                self._write_line(self.form_output, f"- Message: Sanitized ({msg_notes[0]})")
            else:
                self._write_line(self.form_output, "- Message: Valid")
        else:
            self._write_line(self.form_output, f"- Message: Invalid ({msg_errs[0]})")
            for e in msg_errs:
                self._write_line(self.form_output, f"  * {e}")

        self._write_line(self.form_output, "")
        self._write_line(self.form_output, "Sanitized Output:")
        self._write_line(self.form_output, f"Full Name: {fn_clean}")
        self._write_line(self.form_output, f"Email: {em_clean}")
        self._write_line(self.form_output, f"Username: {un_clean}")
        self._write_line(self.form_output, f"Message: {msg_clean}")

        any_sanitized = any(len(v) > 0 for v in sanitize_notes.values())
        if any_sanitized:
            self._write_line(self.form_output, "")
            self._write_line(self.form_output, "Sanitization Summary:")
            for k, notes in sanitize_notes.items():
                if notes:
                    display = k.replace("_", " ").title()
                    self._write_line(self.form_output, f"- {display}: Unsafe characters detected and cleaned.")
                    for n in notes:
                        self._write_line(self.form_output, f"  * {n}")

        self._write_line(self.form_output, "")
        self._write_line(self.form_output, "Process Complete.")


if __name__ == "__main__":
    app = MultiFunctionWebSecurityToolApp()
    app.mainloop()
