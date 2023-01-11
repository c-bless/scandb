from sqlalchemy import Column, Text, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class Scan(Base):
    __tablename__ = 'Scan'
    id = Column(Integer, primary_key=True)
    file_hash = Column(String(128), unique=True, nullable=False)
    name = Column(String(2048), nullable=False)
    type = Column(String(20), nullable=False)
    start = Column(String(20), nullable=True)
    end = Column(String(20), nullable=True)
    elapsed = Column(String(20), nullable=True)
    hosts_total = Column(Integer, nullable=True)
    hosts_up = Column(Integer, nullable=True)
    hosts_down = Column(Integer, nullable=True)
    hosts = relationship("Host", back_populates="scan")

class Host(Base):
    __tablename__ = 'Host'
    id = Column(Integer, primary_key=True)
    address = Column(String(50), nullable=False)
    hostname = Column(String(256),nullable=True)
    os = Column(String(256), nullable=True)
    os_gen = Column(String(50), nullable=True)
    status = Column(String(10), nullable=True)
    scan = relationship("Scan", back_populates="hosts")
    scan_id = Column(Integer, ForeignKey("Scan.id"))
    ports = relationship ("Port", back_populates="host")
    vulns = relationship ("Vuln", back_populates="host")

class Port(Base):
    __tablename__ = 'Port'
    id = Column(Integer, primary_key=True)
    address = Column(String(50), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(50), nullable=False)
    service = Column(Text, nullable=True)
    banner = Column(Text, nullable=True)
    status = Column(Text, nullable=False)
    host_id = Column(Integer, ForeignKey("Host.id"))
    host = relationship ("Host", back_populates="ports")


class Vuln(Base):
    __tablename__ = 'Vuln'
    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("Host.id"))
    host = relationship("Host", back_populates="vulns")
    description = Column(Text, nullable=False)
    synopsis = Column(Text, nullable=True)
    port = Column(Integer, nullable=False)
    protocol = Column(Text, nullable=False)
    service = Column(Text, nullable=False)
    solution = Column(Text, nullable=True)
    severity = Column(Text, nullable=True)
    xref = Column(Text, nullable=True)
    info = Column(Text, nullable=True)
    plugin_id = Column(Text, nullable=False)
    plugin_name = Column(Text, nullable=False)
    plugin = Column(Text, nullable=True)
    plugin_family = Column(Text, nullable=True)
    plugin_output = Column(Text, nullable=True)
    risk = Column(Text, nullable=True)


def init_db(db):
    engine = create_engine('sqlite:///{0}'.format(db))
    Base.metadata.bind = engine
    Base.metadata.create_all(engine)
    return engine

