import json
from copy import deepcopy
from pathlib import Path
from typing import Any, final

import yaml

from ..exceptions import ConfigurationError
from .defaults import DEFAULT_CONFIG  # , ENV_VAR_MAPPINGS, VALIDATION_RULES


class ConfigError(ConfigurationError):
    """Raised when there are configuration-related errors."""

    pass


@final
class Config:
    def __init__(self, config_data: dict[str, Any] | None = None) -> None:
        """Initialize the configuration.

        Args:
            config_data: Optional initial configuration data
        """
        self._config = deepcopy(DEFAULT_CONFIG)
        if config_data:
            self._merge_config(config_data)

    def _merge_config(self, new_config: dict[str, Any]) -> None:
        """Merge new configuration data into existing configuration."""

        def merge_dict(base: dict[str, Any], update: dict[str, Any]) -> None:
            for key, value in update.items():
                if (
                    key in base
                    and isinstance(base[key], dict)
                    and isinstance(value, dict)
                ):
                    merge_dict(base[key], value)
                else:
                    base[key] = value

        merge_dict(self._config, new_config)

    def load_from_file(self, file_path: str | Path) -> None:
        """Load configuration from a file.

        Args:
            file_path: Path to the configuration file

        Raises:
            ConfigError: If file cannot be loaded or parsed
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise ConfigError(f"Configuration file not found: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                if file_path.suffix.lower() in [".yaml", ".yml"]:
                    config_data = yaml.safe_load(f)
                elif file_path.suffix.lower() == ".json":
                    config_data = json.load(f)
                else:
                    raise ConfigError(
                        f"Unsupported configuration file format: {file_path.suffix}"
                    )

            if not isinstance(config_data, dict):
                raise ConfigError(
                    "Configuration file must contain a dictionary"
                )

            self._merge_config(config_data)

        except yaml.YAMLError as e:
            raise ConfigError(f"Invalid YAML in configuration file: {e}")
        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid JSON in configuration file: {e}")
        except Exception as e:
            raise ConfigError(f"Error loading configuration file: {e}")

    def get_submodule_config(self, submodule: str) -> dict[str, Any]:
        """Return one top-level configuration section.

        Args:
            submodule: Name of the section, e.g. ``differential_privacy``.

        Returns:
            The section, or an empty mapping when it is absent. Returning an
            empty mapping rather than ``None`` keeps every caller's
            ``section["key"]`` access from failing with an unhelpful
            ``TypeError`` when configuration is simply missing.

        Raises:
            ConfigError: If the section cannot be read.
        """
        try:
            section = self._config.get(submodule)
        except Exception as e:
            raise ConfigError(f"Error loading submodule configuration: {e}")
        if section is None:
            return {}
        if not isinstance(section, dict):
            raise ConfigError(
                f"Configuration section '{submodule}' must be a mapping, "
                f"got {type(section).__name__}"
            )
        return section
