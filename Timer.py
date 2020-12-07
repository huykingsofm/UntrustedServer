import time

class Timer():
    def start(self, name):
        setattr(self, "s_" + name, time.time())

    def end(self, name):
        setattr(self, name, time.time() - getattr(self, "s_" + name))

    def get(self, name):
        tmp = getattr(self, name)
        delattr(self, name)
        return tmp

    def check(self, name):
        return hasattr(self, name)

        