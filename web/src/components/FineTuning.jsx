import {
  finetuneCards,
  stage4Improvements,
  rlBaselineTable,
  stage4Note,
} from "../data/site.js";
import Section from "./Section.jsx";
import Card, { CardGrid } from "./Card.jsx";
import Note from "./Note.jsx";
import { Table } from "./Results.jsx";

export default function FineTuning() {
  return (
    <Section
      id="rl"
      num="05"
      title="Fine-tuning the triage model"
      subtitle="A research track trains a smaller, specialized triage model with reinforcement learning (GRPO), so the project doesn't depend on an 8B general model for inference. Round 4 implements and measures the reward and dataset improvements, and fixes the baseline the fine-tuned model must beat."
    >
      <CardGrid cols={2}>
        {finetuneCards.map((c) => (
          <Card key={c.title} tag={c.tag} title={c.title} body={c.body} />
        ))}
      </CardGrid>
      <Table data={stage4Improvements} />
      <Table data={rlBaselineTable} />
      <Note
        mark={stage4Note.mark}
        title={stage4Note.title}
        body={stage4Note.body}
      />
    </Section>
  );
}
