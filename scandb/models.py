from peewee import Proxy, SqliteDatabase
from peewee import Model, TextField, IntegerField, ForeignKeyField

database_proxy = Proxy()  # Create a proxy for our db.


class BaseModel(Model):
    class Meta:
        database = database_proxy  # Use proxy for our DB.


class Scan(BaseModel):
    file_hash = TextField(unique=True, null=False)
    name = TextField(null=False)
    type = TextField(null=False)
    start = TextField(null=True)
    end = TextField(null=True)
    elapsed = TextField(null=True)
    hosts_total = IntegerField(null=True)
    hosts_up = IntegerField(null=True)
    hosts_down = IntegerField(null=True)


class Host(BaseModel):
    #hostid = IntegerField(primary_key=True)
    address = TextField(null=False)
    hostname = TextField(null=True)
    os = TextField(null=True)
    os_gen = TextField(null=True)
    status = TextField(null=True)
    scan = ForeignKeyField(Scan, related_name="belongs_to")


class Port(BaseModel):
    #portid = IntegerField(primary_key=True)
    host = ForeignKeyField(Host, related_name="from_host")
    address = TextField(null=False)
    port = IntegerField(null=False)
    protocol = TextField(null=False)
    service = TextField(null=True)
    banner = TextField(null=True)
    status = TextField(null=False)


class Vuln(BaseModel):
    host = ForeignKeyField(Host, related_name="vuln_on_host")
    description = TextField(null=False)
    synopsis = TextField(null=True)
    port = IntegerField(null=False)
    protocol = TextField(null=False)
    service = TextField(null=False)
    solution = TextField(null=True)
    severity = TextField(null=True)
    xref = TextField(null=True)
    info = TextField(null=True)
    plugin_id = TextField(null=False)
    plugin_name = TextField(null=False)
    plugin = TextField(null=True)
    plugin_family = TextField(null=True)
    plugin_output = TextField(null=True)
    risk = TextField(null=True)


def init_db(db):
    database = SqliteDatabase(db)
    database_proxy.initialize(database)
    database.connect()
    database.create_tables(models=[Scan, Host, Port, Vuln], safe=True)
    return database

