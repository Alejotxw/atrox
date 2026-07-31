"""Métrica de precisión del scoring sobre dataset TP/FP etiquetado (HU-016 — DoD).

Ejecuta el agente sobre `tests/fixtures/scoring_dataset.py` (22 hallazgos
etiquetados manualmente) con el umbral por defecto (`ATROX_FP_SCORE_THRESHOLD`,
40) y mide precisión/recall/accuracy de la decisión `probable_fp`. El valor
medido queda documentado en `docs/ai/HU-016-scoring-evaluation.md` — este
test es la fuente de verdad que reproduce esa medición y falla si una
heurística futura degrada la precisión por debajo del umbral aceptado.
"""

from dataclasses import dataclass

from atrox.ai.agents.scoring.models import ScoringRequest
from atrox.ai.agents.scoring.scorer import ConfidenceScoringAgent
from tests.fixtures.scoring_dataset import LABELED_DATASET

# Precisión mínima aceptada para la decisión "no es falso positivo, escalar".
# El dataset incluye a propósito 1 TP difícil (subestimado) y 1 FP difícil
# (sobrestimado) — ver docstrings en scoring_dataset.py — por lo que el 100%
# no es esperable ni deseable como objetivo (indicaría un dataset trivial).
MIN_ACCEPTED_PRECISION = 0.85


@dataclass
class ConfusionMatrix:
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positive + self.false_positive
        return self.true_positive / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positive + self.false_negative
        return self.true_positive / denom if denom else 0.0

    @property
    def accuracy(self) -> float:
        total = self.true_positive + self.false_positive + self.true_negative + self.false_negative
        correct = self.true_positive + self.true_negative
        return correct / total if total else 0.0


def _evaluate() -> ConfusionMatrix:
    agent = ConfidenceScoringAgent()
    matrix = ConfusionMatrix()

    for labeled in LABELED_DATASET:
        result = agent.score(ScoringRequest(finding=labeled.finding))
        predicted_real = not result.probable_fp

        if predicted_real and labeled.is_true_positive:
            matrix.true_positive += 1
        elif predicted_real and not labeled.is_true_positive:
            matrix.false_positive += 1
        elif not predicted_real and not labeled.is_true_positive:
            matrix.true_negative += 1
        else:
            matrix.false_negative += 1

    return matrix


class TestScoringPrecisionOnLabeledDataset:
    def test_dataset_has_both_classes_represented(self) -> None:
        positives = [item for item in LABELED_DATASET if item.is_true_positive]
        negatives = [item for item in LABELED_DATASET if not item.is_true_positive]

        assert len(positives) >= 10
        assert len(negatives) >= 10

    def test_precision_meets_minimum_accepted_threshold(self) -> None:
        matrix = _evaluate()

        assert matrix.precision >= MIN_ACCEPTED_PRECISION, (
            f"Precisión medida {matrix.precision:.3f} por debajo del mínimo "
            f"aceptado {MIN_ACCEPTED_PRECISION}. Matriz: {matrix}"
        )

    def test_confusion_matrix_matches_documented_evaluation(self) -> None:
        """Valores exactos medidos, documentados en docs/ai/HU-016-scoring-evaluation.md.

        Si este test falla porque cambiaste las reglas heurísticas, vuelve a
        correr la suite, toma los valores nuevos de la matriz de confusión y
        actualiza tanto esta aserción como el documento de evaluación.
        """
        matrix = _evaluate()

        assert matrix.true_positive == 10
        assert matrix.false_positive == 1
        assert matrix.true_negative == 10
        assert matrix.false_negative == 1
