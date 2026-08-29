from abc import ABC, abstractmethod

from aegis.assessment import AssessmentContext

class Plugin(ABC):
    name: str
    version: str
    description: str

    @abstractmethod
    def execute(self, context: AssessmentContext):
        """Execute the plugin."""
        raise NotImplementedError