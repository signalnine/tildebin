"""Tests for container_images script."""

import pytest

from boxctl.core.output import Output


DOCKER_IMAGES_OUTPUT = """abc123456789	nginx	latest	150MB
def987654321	ubuntu	22.04	77.8MB
ghi111222333	<none>	<none>	50MB
"""

DOCKER_DANGLING_OUTPUT = """ghi111222333	50MB
"""

DOCKER_PS_OUTPUT = """nginx:latest
ubuntu:22.04
"""

DOCKER_SYSTEM_DF_JSON = """{"Type":"Images","TotalCount":3,"Active":2,"Size":"277.8MB","Reclaimable":"50MB"}
{"Type":"Containers","TotalCount":2,"Active":1,"Size":"100MB","Reclaimable":"0B"}
{"Type":"Build Cache","TotalCount":10,"Active":0,"Size":"2GB","Reclaimable":"2GB"}
"""


class TestContainerImages:
    """Tests for container_images script."""

    def test_no_runtimes_detected(self, mock_context):
        """Returns exit code 2 when no container runtimes found."""
        from scripts.baremetal import container_images

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = container_images.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_docker_healthy(self, mock_context):
        """Returns 0 when Docker images are healthy."""
        from scripts.baremetal import container_images

        ctx = mock_context(
            tools_available=["docker"],
            command_outputs={
                ("docker", "info"): "Server Version: 24.0.0\n",
                ("docker", "images", "--format", "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}"): DOCKER_IMAGES_OUTPUT,
                ("docker", "images", "-f", "dangling=true", "--format", "{{.ID}}\t{{.Size}}"): "",
                ("docker", "ps", "-a", "--format", "{{.Image}}"): DOCKER_PS_OUTPUT,
                ("docker", "system", "df", "--format", "{{json .}}"): DOCKER_SYSTEM_DF_JSON,
            }
        )
        output = Output()

        exit_code = container_images.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total_images"] == 3

    def test_docker_with_dangling(self, mock_context):
        """Detects dangling images."""
        from scripts.baremetal import container_images

        ctx = mock_context(
            tools_available=["docker"],
            command_outputs={
                ("docker", "info"): "Server Version: 24.0.0\n",
                ("docker", "images", "--format", "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}"): DOCKER_IMAGES_OUTPUT,
                ("docker", "images", "-f", "dangling=true", "--format", "{{.ID}}\t{{.Size}}"): DOCKER_DANGLING_OUTPUT,
                ("docker", "ps", "-a", "--format", "{{.Image}}"): DOCKER_PS_OUTPUT,
                ("docker", "system", "df", "--format", "{{json .}}"): DOCKER_SYSTEM_DF_JSON,
            }
        )
        output = Output()

        exit_code = container_images.run([], output, ctx)

        assert output.data["runtimes"][0]["dangling_count"] == 1
        assert output.data["summary"]["total_dangling_images"] == 1

    def test_high_dangling_count_warning(self, mock_context):
        """Returns 1 when dangling count exceeds threshold."""
        from scripts.baremetal import container_images

        # Create many dangling images
        dangling_output = "\n".join([f"img{i:06d}\t10MB" for i in range(15)])

        ctx = mock_context(
            tools_available=["docker"],
            command_outputs={
                ("docker", "info"): "Server Version: 24.0.0\n",
                ("docker", "images", "--format", "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}"): DOCKER_IMAGES_OUTPUT,
                ("docker", "images", "-f", "dangling=true", "--format", "{{.ID}}\t{{.Size}}"): dangling_output,
                ("docker", "ps", "-a", "--format", "{{.Image}}"): DOCKER_PS_OUTPUT,
                ("docker", "system", "df", "--format", "{{json .}}"): "",
            }
        )
        output = Output()

        exit_code = container_images.run(["--dangling-warn", "10"], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["total_dangling_images"] == 15
        assert any("dangling" in i["message"].lower() for i in output.data["issues"])

    def test_large_build_cache_warning(self, mock_context):
        """Returns 1 when build cache is large."""
        from scripts.baremetal import container_images

        large_cache = """{"Type":"Build Cache","TotalCount":100,"Active":0,"Size":"10GB","Reclaimable":"10GB"}
"""

        ctx = mock_context(
            tools_available=["docker"],
            command_outputs={
                ("docker", "info"): "Server Version: 24.0.0\n",
                ("docker", "images", "--format", "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}"): DOCKER_IMAGES_OUTPUT,
                ("docker", "images", "-f", "dangling=true", "--format", "{{.ID}}\t{{.Size}}"): "",
                ("docker", "ps", "-a", "--format", "{{.Image}}"): DOCKER_PS_OUTPUT,
                ("docker", "system", "df", "--format", "{{json .}}"): large_cache,
            }
        )
        output = Output()

        exit_code = container_images.run([], output, ctx)

        assert exit_code == 1
        assert any("build cache" in i["message"].lower() for i in output.data["issues"])

    def test_specific_runtime(self, mock_context):
        """Can specify specific runtime."""
        from scripts.baremetal import container_images

        ctx = mock_context(
            tools_available=["docker", "podman"],
            command_outputs={
                ("docker", "info"): "Server Version: 24.0.0\n",
                ("docker", "images", "--format", "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}"): DOCKER_IMAGES_OUTPUT,
                ("docker", "images", "-f", "dangling=true", "--format", "{{.ID}}\t{{.Size}}"): "",
                ("docker", "ps", "-a", "--format", "{{.Image}}"): DOCKER_PS_OUTPUT,
                ("docker", "system", "df", "--format", "{{json .}}"): "",
            }
        )
        output = Output()

        exit_code = container_images.run(["--runtime", "docker"], output, ctx)

        assert exit_code == 0
        assert len(output.data["runtimes"]) == 1
        assert output.data["runtimes"][0]["runtime"] == "docker"

    def test_reclaimable_threshold(self, mock_context):
        """Returns 1 when reclaimable space exceeds threshold."""
        from scripts.baremetal import container_images

        # Large reclaimable
        large_reclaimable = """{"Type":"Build Cache","TotalCount":100,"Active":0,"Size":"10GB","Reclaimable":"10GB"}
"""

        ctx = mock_context(
            tools_available=["docker"],
            command_outputs={
                ("docker", "info"): "Server Version: 24.0.0\n",
                ("docker", "images", "--format", "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}"): DOCKER_IMAGES_OUTPUT,
                ("docker", "images", "-f", "dangling=true", "--format", "{{.ID}}\t{{.Size}}"): "img1\t6GB\n",
                ("docker", "ps", "-a", "--format", "{{.Image}}"): DOCKER_PS_OUTPUT,
                ("docker", "system", "df", "--format", "{{json .}}"): large_reclaimable,
            }
        )
        output = Output()

        exit_code = container_images.run(["--reclaimable-warn", "5"], output, ctx)

        assert exit_code == 1
        assert any("reclaimable" in i["message"].lower() for i in output.data["issues"])

    def test_podman_runtime(self, mock_context):
        """Can analyze Podman runtime."""
        from scripts.baremetal import container_images

        ctx = mock_context(
            tools_available=["podman"],
            command_outputs={
                ("podman", "version"): "Version: 4.0.0\n",
                ("podman", "images", "--format", "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}"): "abc123\tnginx\tlatest\t100MB\n",
                ("podman", "images", "-f", "dangling=true", "--format", "{{.ID}}\t{{.Size}}"): "",
            }
        )
        output = Output()

        exit_code = container_images.run(["--runtime", "podman"], output, ctx)

        assert exit_code == 0
        assert output.data["runtimes"][0]["runtime"] == "podman"
        assert output.data["summary"]["total_images"] == 1
