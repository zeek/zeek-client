# The Zeek Cluster Management Client

This is an experimental version of the future client application for managing
Zeek clusters. `zeek-client` connects to Zeek's _cluster controller_, a Zeek
instance that exists in every cluster. The controller in turn is connected to the
cluster's _instances_, physical machines each running an _agent_ that maintains
the _data nodes_ composing a typical Zeek cluster (with manager, workers,
proxies, and loggers).
