variable "VERSION" {}

variable "IMAGE_REPOSITORY" {
  default = "code-marketplace"
}

group "default" {
  targets = ["code-marketplace"]
}

target "code-marketplace" {
  dockerfile = "./Dockerfile"
  tags = [
    "${IMAGE_REPOSITORY}:${VERSION}",
  ]
  platforms = ["linux/amd64", "linux/arm64"]
}
