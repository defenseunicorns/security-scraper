from itemadapter import ItemAdapter
import time

from pathlib import Path

from ruamel.yaml import YAML


# pipeline to add crawl date/first seen
# A first-scan config setting too maybe to backfill the DB with everything ignored or sorted as old


# https://stackoverflow.com/a/33300001
def str_presenter(dumper, data):
    if "\n" in data:  # check for multiline string
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


def struct_time_representer(dumper, data):
    serialized = time.strftime("%Y-%m-%dT%H:%M:%SZ", data)
    return dumper.represent_scalar("tag:yaml.org,2002:str", serialized)


# yaml.add_representer(str, str_presenter)
# yaml.representer.SafeRepresenter.add_representer(str, str_presenter)


class YAMLFilesExportPipeline:
    """Distribute items across multiple JSON files according to their 'spider', 'product', and 'id' fields"""

    def __init__(self):
        self.yaml = YAML()
        self.yaml.default_flow_style = False
        self.yaml.representer.add_representer(str, str_presenter)
        self.yaml.representer.add_representer(time.struct_time, struct_time_representer)

    def process_item(self, item, spider):
        output_dir = spider.settings.get("OUTPUT_DIRECTORY")
        if not output_dir:
            return item

        adapter = ItemAdapter(item)
        spider_name = adapter["spider"]
        product = adapter["product"]
        id_ = adapter["id"]

        # TODO: track if any files get clobbered and throw error

        path = Path(output_dir, spider_name, product, f"{id_}.yaml")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w") as f:
            self.yaml.dump(adapter.asdict(), f)

        return item
