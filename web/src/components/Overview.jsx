import { overviewCards } from "../data/site.js";
import Section from "./Section.jsx";
import Card, { CardGrid } from "./Card.jsx";

export default function Overview() {
  return (
    <Section
      id="overview"
      num="01"
      title="The problem it solves"
      subtitle="Static analyzers are high-recall and low-precision: they find most real bugs but bury them under false alarms, so engineers stop reading the output. vulnscan keeps the analyzers' recall and adds a triage layer that removes noise — then proves the trade-off on labelled code instead of trusting the model."
    >
      <CardGrid cols={3}>
        {overviewCards.map((c) => (
          <Card key={c.title} tag={c.tag} title={c.title} body={c.body} />
        ))}
      </CardGrid>
    </Section>
  );
}
