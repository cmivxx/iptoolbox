# static/

Static assets served by Flask at `/static/<file>`.

To show a marketing image in the page hero, drop a file named **`hero.png`**
here and redeploy (`docker compose up -d --build`). If it's absent, the hero
shows a placeholder instead.
