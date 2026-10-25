import { heroStats } from "../data/site.js";
import styles from "./StatGrid.module.css";

export default function StatGrid() {
  return (
    <div className={styles.stats}>
      {heroStats.map((s) => (
        <div key={s.l} className={styles.stat}>
          <div className={styles.n}>{s.n}</div>
          <div className={styles.l}>{s.l}</div>
        </div>
      ))}
    </div>
  );
}
