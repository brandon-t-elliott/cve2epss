# CVE to EPSS

A simple one-page web app that allows users to enter a CVE ID (e.g. `CVE-1999-0001`) and fetch EPSS (Exploit Prediction Scoring System) data via the [FIRST.org EPSS API](https://first.org/epss/).

I really just wanted a quick way to see the EPSS data for a single CVE ID.

It's not meant to be an all-encompassing app.

## Try it Out

[https://cve2epss.com](https://cve2epss.com)

## Running Locally

```bash
git clone https://github.com/brandon-t-elliott/cve2epss.git
cd cve2epss
npm install
npm run dev
```
 
Then open [http://localhost:3000](http://localhost:3000)

## License

MIT — free to use and modify.
