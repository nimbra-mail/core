//! The page the browser shows when a sign-in comes back to Nimbra (Google or Microsoft):
//! the app icon on the Inbox Zero glow, and a line on what happened. Everything it needs
//! (the icon, the fonts) is inside the page, and its content security policy lets it load
//! nothing else and run no script.

use base64::Engine;

/// How a sign-in ended, as the page tells it.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Outcome {
    Connected,
    Cancelled,
}

/// The policy the page is served with: inline styles, and images and fonts from the page
/// itself, nothing else.
pub const POLICY: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; \
                          font-src data:; base-uri 'none'; form-action 'none'; \
                          frame-ancestors 'none'";

const ICON_LIGHT: &[u8] = include_bytes!("../assets/app-icon.png");
const ICON_DARK: &[u8] = include_bytes!("../assets/app-icon-dark.png");
const SERIF: &[u8] = include_bytes!("../assets/fonts/InstrumentSerif-Regular.ttf");
const SERIF_ITALIC: &[u8] = include_bytes!("../assets/fonts/InstrumentSerif-Italic.ttf");
const SANS: &[u8] = include_bytes!("../assets/fonts/Geist-Regular.ttf");

fn data(mime: &str, bytes: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    format!("data:{mime};base64,{encoded}")
}

/// The whole page. Its words are fixed here: nothing from the request is put in it.
pub fn html(outcome: Outcome) -> String {
    let (title, lead, accent, text) = match outcome {
        Outcome::Connected => (
            "Nimbra is connected",
            "You’re",
            "connected.",
            "Your account is ready in Nimbra. You can close this tab and go back to the app.",
        ),
        Outcome::Cancelled => (
            "Sign-in cancelled",
            "Sign-in",
            "cancelled.",
            "Nothing was changed. You can close this tab and try again from Nimbra.",
        ),
    };
    let (light, dark) = (data("image/png", ICON_LIGHT), data("image/png", ICON_DARK));
    let (serif, italic, sans) = (
        data("font/ttf", SERIF),
        data("font/ttf", SERIF_ITALIC),
        data("font/ttf", SANS),
    );
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{title}</title>
<style>
@font-face {{ font-family: "Instrument Serif"; src: url({serif}) format("truetype"); }}
@font-face {{ font-family: "Instrument Serif"; font-style: italic; src: url({italic}) format("truetype"); }}
@font-face {{ font-family: "Geist"; src: url({sans}) format("truetype"); }}
:root {{
  --bg: #f4f2ee; --text: #17151f; --text2: #5d5a68;
  --glow1: rgba(139, 124, 255, .42); --glow2: rgba(255, 122, 182, .30); --glow3: rgba(255, 176, 92, .22);
  --shadow: rgba(76, 58, 160, .28);
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #0e0e14; --text: #f5f3ef; --text2: #a6a2b4;
    --glow1: rgba(124, 92, 255, .55); --glow2: rgba(226, 72, 150, .38); --glow3: rgba(255, 150, 70, .20);
    --shadow: rgba(0, 0, 0, .55);
  }}
}}
* {{ box-sizing: border-box; }}
html, body {{ height: 100%; margin: 0; }}
body {{
  display: grid; place-items: center; padding: 24px; overflow: hidden;
  background:
    radial-gradient(60% 55% at 18% 12%, var(--glow1), transparent 70%),
    radial-gradient(50% 50% at 88% 86%, var(--glow2), transparent 70%),
    radial-gradient(40% 40% at 42% 96%, var(--glow3), transparent 70%),
    var(--bg);
  color: var(--text);
  font: 17px/1.55 "Geist", -apple-system, system-ui, sans-serif;
  -webkit-font-smoothing: antialiased;
}}
main {{ max-width: 560px; text-align: center; animation: rise .7s cubic-bezier(.22, 1, .36, 1) both; }}
img {{ width: 132px; height: 132px; filter: drop-shadow(0 18px 36px var(--shadow)); }}
h1 {{
  margin: 28px 0 12px; font: 400 64px/1.05 "Instrument Serif", Georgia, serif;
  letter-spacing: -.01em;
}}
h1 em {{ font-style: italic; }}
p {{ margin: 0 auto; max-width: 420px; color: var(--text2); }}
@keyframes rise {{ from {{ opacity: 0; transform: translateY(10px); }} }}
@media (prefers-reduced-motion: reduce) {{ main {{ animation: none; }} }}
@media (max-width: 520px) {{ h1 {{ font-size: 46px; }} img {{ width: 104px; height: 104px; }} }}
</style>
</head>
<body>
<main>
<picture>
<source media="(prefers-color-scheme: dark)" srcset="{dark}">
<img src="{light}" alt="Nimbra">
</picture>
<h1>{lead} <em>{accent}</em></h1>
<p>{text}</p>
</main>
</body>
</html>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_outcome_says_what_happened() {
        let connected = html(Outcome::Connected);
        assert!(connected.contains("<em>connected.</em>"));
        assert!(connected.contains("close this tab"));
        let cancelled = html(Outcome::Cancelled);
        assert!(cancelled.contains("<em>cancelled.</em>"));
        assert!(cancelled.contains("Nothing was changed"));
    }

    #[test]
    fn the_page_needs_nothing_from_outside() {
        let page = html(Outcome::Connected);
        assert!(!page.contains("http://") && !page.contains("https://"));
        assert!(!page.contains("<script"));
        assert!(POLICY.contains("default-src 'none'"));
    }
}
