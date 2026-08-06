"""Módulo de generación de reportes ejecutivos (HU-023) y técnicos (HU-024) para Atrox."""

from atrox.reports.generator import ExecutiveReportGenerator
from atrox.reports.models import (
    ExecutiveReportData,
    SeverityHeatmap,
    TechnicalFindingItem,
    TechnicalReportData,
    TopRiskItem,
)
from atrox.reports.technical_generator import TechnicalReportGenerator

__all__ = [
    "ExecutiveReportData",
    "SeverityHeatmap",
    "TopRiskItem",
    "ExecutiveReportGenerator",
    "TechnicalFindingItem",
    "TechnicalReportData",
    "TechnicalReportGenerator",
]
