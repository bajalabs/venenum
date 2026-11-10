/** The test vector published in docs/signing.md; the Node and Python examples must produce the same signature. */
export const VECTOR = {
  caller: "example-app",
  t: 1700000000,
  key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  body: '{"url":"https://files.example.com/report.pdf","sha256":"2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae","size":3,"ref":"doc-42"}',
  v1: "e3a1cc5806ef5d189b9ababace90ada8141f69d3eeeb2a7a208072a94d1c77ea",
};
