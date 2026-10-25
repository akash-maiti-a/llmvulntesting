import { repoUrl, profileUrl } from "../data/site.js";
import styles from "./Footer.module.css";

export default function Footer() {
  return (
    <footer className={styles.footer}>
      <div className={`container ${styles.inner}`}>
        <div>
          <div className={styles.brand}>
            <span className={styles.dot} />
            vulnscan
          </div>
          <div className={styles.tag}>
            LLM-assisted vulnerability scanning · measured, reproducible, local.
          </div>
        </div>
        <div className={styles.links}>
          <a href={repoUrl} target="_blank" rel="noopener">
            Repository
          </a>
          <a href={profileUrl} target="_blank" rel="noopener">
            GitHub profile
          </a>
          <a href="#overview">Back to top ↑</a>
        </div>
      </div>
    </footer>
  );
}
