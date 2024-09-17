import copy, logging
def nested_access(data, path):
    if isinstance(path, str):
        keys = path.split('.')
    else:
        keys = path
    current = data

    # logger = logging.getLogger("nc-mis")

    try:
        while len(keys) > 0:
            key = keys.pop(0)
            if isinstance(current, list):
                lists = [nested_access(x, copy.deepcopy(keys)) for x in current]
                if len(lists) == 1 and isinstance(lists[0], list):
                    # logger.debug(lists[0])
                    return lists[0]
                # logger.debug(lists)
                return lists
            else:
                
                current = current.get(key)
                # logger.debug(current)
        return current
    except AttributeError:
        # logger.debug('Attribute error')
        return None