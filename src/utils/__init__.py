# Utilities module
# Note: validation is imported directly by modules that need it to avoid circular imports
# ExportImport is imported lazily to avoid circular import with database

def get_export_import():
    """Lazy import of ExportImport to avoid circular imports."""
    from .export_import import ExportImport
    return ExportImport

__all__ = ['get_export_import']
