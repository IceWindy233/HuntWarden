export interface RemoteArtifact {
  artifactToken: string;
  sha256: string;
  size: number;
  expiresAt: string;
}

export interface ArtifactTransferResult {
  sha256: string;
  size: number;
}
