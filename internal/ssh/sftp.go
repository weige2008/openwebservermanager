package sshsession

import (
	"io"
	"os"

	"github.com/pkg/sftp"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/store"
)

type RemoteFile interface {
	io.Reader
	io.Writer
	io.Seeker
	io.Closer
}

type FileClient struct {
	client *sftp.Client
	ssh    io.Closer
}

func OpenFileClient(server model.Server, credential model.Credential, secret store.CredentialSecret, knownHostsPath string, dialContext DialContextFunc) (*FileClient, error) {
	sshClient, err := dial(server, credential, secret, knownHostsPath, dialContext)
	if err != nil {
		return nil, err
	}
	client, err := sftp.NewClient(sshClient)
	if err != nil {
		_ = sshClient.Close()
		return nil, err
	}
	return &FileClient{client: client, ssh: sshClient}, nil
}

func (c *FileClient) Close() error {
	if c == nil {
		return nil
	}
	var first error
	if c.client != nil {
		first = c.client.Close()
	}
	if c.ssh != nil {
		if err := c.ssh.Close(); first == nil {
			first = err
		}
	}
	return first
}

func (c *FileClient) Getwd() (string, error) {
	return c.client.Getwd()
}

func (c *FileClient) ReadDir(path string) ([]os.FileInfo, error) {
	return c.client.ReadDir(path)
}

func (c *FileClient) Stat(path string) (os.FileInfo, error) {
	return c.client.Stat(path)
}

func (c *FileClient) Open(path string) (RemoteFile, error) {
	return c.client.Open(path)
}

func (c *FileClient) Create(path string) (RemoteFile, error) {
	return c.client.Create(path)
}

func (c *FileClient) Rename(oldPath, newPath string) error {
	return c.client.Rename(oldPath, newPath)
}

func (c *FileClient) Remove(path string) error {
	return c.client.Remove(path)
}

func (c *FileClient) Chmod(path string, mode os.FileMode) error {
	return c.client.Chmod(path, mode)
}
