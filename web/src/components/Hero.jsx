import { repoUrl } from "../data/site.js";
import StatGrid from "./StatGrid.jsx";
import styles from "./Hero.module.css";

export default function Hero() {
  return (
    <section className={styles.hero}>
      <div className="container">
        <div className={styles.eyebrow}>
          Static analysis · LLM triage · measured against ground truth
        </div>
        <h1 className={styles.h1}>
          An LLM that <span className={styles.thin}>triages</span>
          <br />
          vulnerability scanner noise.
        </h1>
        <p className={styles.lede}>
          Semgrep and Pysa flag candidate security bugs; a local LLM reads each one in
          context and decides whether it is real. Every verdict is scored against
          hand-built ground truth from deliberately vulnerable apps, a synthetic
          benchmark, and real CVEs.
        </p>
        <div className={styles.btns}>
          <a className={`${styles.btn} ${styles.primary}`} href="#results">
            See the results
          </a>
          <a className={`${styles.btn} ${styles.ghost}`} href="#pipeline">
            How it works
          </a>
          <a
            className={`${styles.btn} ${styles.ghost}`}
            href={repoUrl}
            target="_blank"
            rel="noopener"
          >
            View source
          </a>
        </div>
        <StatGrid />
      </div>
    </section>
  );
}
