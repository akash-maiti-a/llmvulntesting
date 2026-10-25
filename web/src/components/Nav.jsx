import { navLinks, repoUrl } from "../data/site.js";
import styles from "./Nav.module.css";

export default function Nav() {
  return (
    <header className={styles.nav}>
      <div className={`container ${styles.inner}`}>
        <span className={styles.brand}>
          <span className={styles.dot} />
          vulnscan
        </span>
        <nav className={styles.links}>
          {navLinks.map((l) => (
            <a key={l.href} href={l.href}>
              {l.label}
            </a>
          ))}
          <a className={styles.cta} href={repoUrl} target="_blank" rel="noopener">
            GitHub ↗
          </a>
        </nav>
      </div>
    </header>
  );
}
