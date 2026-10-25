# vulnscan site

Source for the project site at **https://akash-maiti-a.github.io/llmvulntesting/**.
React + Vite, with components, CSS Modules, and page content kept separate.

## Structure

```
web/
  index.html              Vite entry template
  vite.config.js          base: "/llmvulntesting/"
  src/
    main.jsx              React entry
    App.jsx               composes the sections
    index.css             global tokens, reset, base styles
    data/site.js          all page copy and numbers (no markup)
    components/
      Nav, Hero, StatGrid
      Section, Card, Note (reusable primitives)
      Overview, Pipeline, Method, Results, FineTuning, Engineering, Footer
      *.module.css        component-scoped styles
```

## Develop

```sh
cd web
npm install
npm run dev        # local dev server
npm run build      # production build -> web/dist
npm run preview    # serve the build locally
```

## Deploy

The built site is published on the `gh-pages` branch (served from its root).
After `npm run build`, copy `web/dist/` to the branch root and push:

```sh
cp -r web/dist/index.html web/dist/assets ./
git add index.html assets web
git commit -m "Rebuild site"
git push origin gh-pages
```
