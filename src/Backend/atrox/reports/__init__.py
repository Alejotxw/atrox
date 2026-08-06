"""Módulo de generación de reportes ejecutivos y técnicos para Atrox (HU-023)."""

from atrox.reports.generator import ExecutiveReportGenerator
from atrox.reports.models import ExecutiveReportData, SeverityHeatmap, TopRiskItem

__all__ = ["ExecutiveReportData", "SeverityHeatmap", "TopRiskItem", "ExecutiveReportGenerator"]
