"""Shared UNO dialog primitives."""


class DialogBuilder:
    """Small factory around UnoControlDialog and its model."""

    def __init__(self, title, width, height, background_color=None, log_func=None):
        import uno

        self._uno = uno
        self._log = log_func or (lambda _message: None)
        self.width = width
        self.height = height
        self.ctx = uno.getComponentContext()
        self.sm = self.ctx.getServiceManager()
        self.dialog = self.sm.createInstanceWithContext(
            "com.sun.star.awt.UnoControlDialog", self.ctx
        )
        self.model = self.sm.createInstanceWithContext(
            "com.sun.star.awt.UnoControlDialogModel", self.ctx
        )
        self.dialog.setModel(self.model)
        self.dialog.setVisible(False)
        self.dialog.setTitle(title)

        from com.sun.star.awt.PosSize import SIZE

        self.dialog.setPosSize(0, 0, width, height, SIZE)
        if background_color is not None:
            try:
                self.model.BackgroundColor = background_color
            except Exception:
                pass

    def create(self, name):
        return self.sm.createInstanceWithContext(name, self.ctx)

    def add(self, name, ctrl_type, x, y, width, height, props):
        from com.sun.star.awt.PosSize import POSSIZE

        try:
            ctrl_model = self.model.createInstance(
                f"com.sun.star.awt.UnoControl{ctrl_type}Model"
            )
        except Exception as exc:
            self._log(f"Dialog control type unsupported: name={name} type={ctrl_type} error={str(exc)}")
            return None
        try:
            self.model.insertByName(name, ctrl_model)
        except Exception as exc:
            self._log(f"Dialog insert failed: name={name} type={ctrl_type} error={str(exc)}")
            return None

        control = self.dialog.getControl(name)
        try:
            control.setPosSize(x, y, width, height, POSSIZE)
        except Exception as exc:
            self._log(f"Dialog size failed: name={name} type={ctrl_type} error={str(exc)}")

        for key, value in props.items():
            try:
                setattr(ctrl_model, key, value)
            except Exception as exc:
                self._log(f"Dialog prop unsupported: control={name} type={ctrl_type} prop={key} error={str(exc)}")
        return control

    def current_window(self):
        frame = self.create("com.sun.star.frame.Desktop").getCurrentFrame()
        return frame.getContainerWindow() if frame else None

    def create_peer(self, window=None):
        toolkit = self.create("com.sun.star.awt.Toolkit")
        self.dialog.createPeer(toolkit, window)
        return toolkit

    def position(self, x=None, y=None, window=None, use_twip=False):
        from com.sun.star.awt.PosSize import POS

        px = py = None
        if x is not None and y is not None and use_twip:
            from com.sun.star.util.MeasureUnit import TWIP

            ps = self.dialog.convertSizeToPixel(
                self._uno.createUnoStruct("com.sun.star.awt.Size", x, y),
                TWIP,
            )
            px, py = ps.Width, ps.Height
        elif x is not None and y is not None:
            px, py = x, y
        elif window is not None:
            ps = window.getPosSize()
            px = ps.Width / 2 - self.width / 2
            py = ps.Height / 2 - self.height / 2

        if px is not None and py is not None:
            self.dialog.setPosSize(px, py, 0, 0, POS)

    def execute(self):
        return self.dialog.execute()

    def dispose(self):
        try:
            self.dialog.dispose()
        except Exception:
            pass
