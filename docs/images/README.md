# Diagrams

The PNGs here are generated from the HTML in `src/`, not drawn by hand, so a
change to the system means editing a page rather than re-creating an image.

```bash
node docs/images/src/serve.js        # serves them on 127.0.0.1:8791
# then screenshot each page at 2x device scale
```

| Image | Answers |
|---|---|
| `flow.png` | What leaves the machine, and what comes back |
| `architecture.png` | How the five mechanisms keep it running |
| `failure-modes.png` | The bugs, and the one shape they share |

Rendered dark-theme at 2x so they stay sharp on high-DPI screens and sit
naturally in dark-mode readers. They contain only template values —
`example.com`, RFC 5737 documentation addresses, and the fixture name used
throughout this repository.
