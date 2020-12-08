class done():
    def __init__(self, value, attributes: dict = None, inherit_from = None):
        assert isinstance(attributes, dict) or attributes == None, "attributes must be a dictionary"
        assert attributes == None or "value" not in attributes.keys(), "attributes must be not include key \"value\""
        assert isinstance(inherit_from, done) or inherit_from == None, "Must inherit from a done object"
        
        self.value = value
        
        if attributes != None:
            for key in attributes:
                setattr(self, key, attributes[key])
        
        if inherit_from != None:
            for attr in inherit_from.__dict__:
                if attr != "value":
                    setattr(self, attr, getattr(inherit_from, attr))