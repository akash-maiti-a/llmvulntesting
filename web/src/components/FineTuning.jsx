import { finetuneCards } from "../data/site.js";
import Section from "./Section.jsx";
import Card, { CardGrid } from "./Card.jsx";

export default function FineTuning() {
  return (
    <Section
      id="rl"
      num="05"
      title="Fine-tuning the triage model"
      subtitle="A research track (round 3) trains a smaller, specialized triage model with reinforcement learning, so the project doesn't depend on an 8B general model for inference."
    >
      <CardGrid cols={2}>
        {finetuneCards.map((c) => (
          <Card key={c.title} tag={c.tag} title={c.title} body={c.body} />
        ))}
      </CardGrid>
    </Section>
  );
}
