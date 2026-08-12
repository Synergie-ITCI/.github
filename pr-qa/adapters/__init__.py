from .docker import DockerAdapter
from .dotnet import DotnetAdapter
from .github_actions import GitHubActionsAdapter
from .go import GoAdapter
from .gradle import GradleAdapter
from .java import JavaAdapter
from .kubernetes import KubernetesAdapter
from .node import NodeAdapter
from .php import PhpAdapter
from .python import PythonAdapter
from .rust import RustAdapter
from .sql import SqlAdapter
from .swift import SwiftAdapter
from .terraform import TerraformAdapter


ADAPTERS = [
    PhpAdapter(),
    NodeAdapter(),
    PythonAdapter(),
    GoAdapter(),
    GradleAdapter(),
    SwiftAdapter(),
    JavaAdapter(),
    DotnetAdapter(),
    RustAdapter(),
    SqlAdapter(),
    DockerAdapter(),
    TerraformAdapter(),
    KubernetesAdapter(),
    GitHubActionsAdapter(),
]
