package sshw

import (
	"bufio"
	"fmt"
	"github.com/abiosoft/ishell/v2"
	"github.com/abiosoft/readline"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	DefaultCiphers = []string{
		"aes128-ctr",
		"aes192-ctr",
		"aes256-ctr",
		"aes128-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"arcfour256",
		"arcfour128",
		"arcfour",
		"aes128-cbc",
		"3des-cbc",
		"blowfish-cbc",
		"cast128-cbc",
		"aes192-cbc",
		"aes256-cbc",
	}
)

type Client interface {
	Close() error
	Login() error
	StartSession() error
}

type defaultClient struct {
	*gossh.Client
	clientConfig *gossh.ClientConfig
	node         *Node
}

type stdioClient struct {
	*gossh.Client
	clientConfig *gossh.ClientConfig
	node         *Node
	shell        *ishell.Shell
	stdin        io.ReadCloser
	stdout       io.Writer
	stderr       io.Writer
	width        int
	height       int
	winch        <-chan ssh.Window
}

func genSSHConfigWithStdio(node *Node, winch <-chan ssh.Window, w, h int, stdin io.ReadCloser, stdout io.Writer, stderr io.Writer) *stdioClient {
	shell := ishell.NewWithConfig(&readline.Config{
		Prompt: fmt.Sprintf("%s@%s:%d's password:", node.User, node.Host, node.Port),
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	})

	var err error
	var authMethods []gossh.AuthMethod

	var pemBytes []byte
	if node.KeyPath == "" {
		pemBytes, err = ioutil.ReadFile(path.Join(node.User, ".ssh/id_rsa"))
	} else {
		pemBytes, err = ioutil.ReadFile(node.KeyPath)
	}

	if err != nil && node.PrivateKey == "" {
		l.Error(err)
	} else {
		pemBytes = []byte(node.PrivateKey)
		var signer gossh.Signer
		if node.Passphrase != "" {
			signer, err = gossh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(node.Passphrase))
		} else {
			signer, err = gossh.ParsePrivateKey(pemBytes)
		}
		if err != nil {
			l.Error(err)
		} else {
			authMethods = append(authMethods, gossh.PublicKeys(signer))
		}
	}

	password := node.password()

	if password != nil {
		authMethods = append(authMethods, password)
	}
	authMethods = append(authMethods, gossh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, 0, len(questions))
		for i, q := range questions {
			fmt.Print(q)
			if echos[i] {
				scan := bufio.NewScanner(stdin)
				if scan.Scan() {
					answers = append(answers, scan.Text())
				}
				err := scan.Err()
				if err != nil {
					return nil, err
				}
			} else {
				fmt.Fprintf(stdout, "%s@%s's password:", node.User, node.Host)
				log.Println("-------------------------------")
				passwd := shell.ReadPassword()
				defer shell.Close()
				fmt.Println()
				answers = append(answers, passwd)
			}
		}
		return answers, nil
	}))

	config := &gossh.ClientConfig{
		User:            node.user(),
		Auth:            authMethods,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         time.Second * 10,
	}

	config.SetDefaults()
	config.Ciphers = append(config.Ciphers, DefaultCiphers...)

	return &stdioClient{
		clientConfig: config,
		shell:        shell,
		node:         node,
		stdin:        stdin,
		stdout:       stdout,
		stderr:       stderr,
		width:        w,
		height:       h,
		winch:        winch,
	}
}

func genSSHConfig(node *Node) *defaultClient {
	u, err := user.Current()
	if err != nil {
		l.Error(err)
		return nil
	}

	var authMethods []gossh.AuthMethod

	var pemBytes []byte
	if node.KeyPath == "" {
		pemBytes, err = ioutil.ReadFile(path.Join(u.HomeDir, ".ssh/id_rsa"))
	} else {
		pemBytes, err = ioutil.ReadFile(node.KeyPath)
	}
	if err != nil {
		l.Error(err)
	} else {
		var signer gossh.Signer
		if node.Passphrase != "" {
			signer, err = gossh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(node.Passphrase))
		} else {
			signer, err = gossh.ParsePrivateKey(pemBytes)
		}
		if err != nil {
			l.Error(err)
		} else {
			authMethods = append(authMethods, gossh.PublicKeys(signer))
		}
	}

	password := node.password()

	if password != nil {
		authMethods = append(authMethods, password)
	}

	authMethods = append(authMethods, gossh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, 0, len(questions))
		for i, q := range questions {
			fmt.Print(q)
			if echos[i] {
				scan := bufio.NewScanner(os.Stdin)
				if scan.Scan() {
					answers = append(answers, scan.Text())
				}
				err := scan.Err()
				if err != nil {
					return nil, err
				}
			} else {
				b, err := terminal.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return nil, err
				}
				fmt.Println()
				answers = append(answers, string(b))
			}
		}
		return answers, nil
	}))

	config := &gossh.ClientConfig{
		User:            node.user(),
		Auth:            authMethods,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         time.Second * 10,
	}

	config.SetDefaults()
	config.Ciphers = append(config.Ciphers, DefaultCiphers...)

	return &defaultClient{
		clientConfig: config,
		node:         node,
	}
}

func NewClient(node *Node) Client {
	return genSSHConfig(node)
}

func NewClientWithStdio(node *Node, winch <-chan ssh.Window, w, h int, stdin io.ReadCloser, stdout, stderr io.Writer) Client {
	return genSSHConfigWithStdio(node, winch, w, h, stdin, stdout, stderr)
}

func (c *stdioClient) Close() error {
	return c.Close()
}
func (c *stdioClient) Login() error {
	host := c.node.Host
	port := strconv.Itoa(c.node.port())
	jNodes := c.node.Jump

	var client *gossh.Client

	if len(jNodes) > 0 {
		jNode := jNodes[0]
		jc := genSSHConfigWithStdio(jNode, c.winch, c.width, c.height, c.stdin, c.stdout, c.stderr)
		proxyClient, err := gossh.Dial("tcp", net.JoinHostPort(jNode.Host, strconv.Itoa(jNode.port())), jc.clientConfig)
		if err != nil {
			l.Error(err)
			return err
		}
		conn, err := proxyClient.Dial("tcp", net.JoinHostPort(host, port))
		if err != nil {
			l.Error(err)
			return err
		}
		ncc, chans, reqs, err := gossh.NewClientConn(conn, net.JoinHostPort(host, port), c.clientConfig)
		if err != nil {
			l.Error(err)
			return err
		}
		client = gossh.NewClient(ncc, chans, reqs)
	} else {
		client1, err := gossh.Dial("tcp", net.JoinHostPort(host, port), c.clientConfig)
		client = client1
		if err != nil {
			msg := err.Error()
			// use terminal password retry
			if strings.Contains(msg, "no supported methods remain") && !strings.Contains(msg, "password") {
				fmt.Fprintf(c.stdout, "%s@%s's password:", c.node.User, host)
				log.Println("**********************************")
				shell := ishell.NewWithConfig(&readline.Config{
					Prompt: fmt.Sprintf("%s@%s:%d's password:", c.node.User, c.node.Host, c.node.Port),
					Stdin:  c.stdin,
					Stdout: c.stdout,
					Stderr: c.stderr,
				})
				p := shell.ReadLine()
				if p != "" {
					c.clientConfig.Auth = append(c.clientConfig.Auth, gossh.Password(p))
				}
				defer shell.Close()
				fmt.Println()
				client, err = gossh.Dial("tcp", net.JoinHostPort(host, port), c.clientConfig)
			}
		}
		if err != nil {
			l.Error(err)
			return err
		}
	}

	l.Infof("connect server ssh -p %d %s@%s version: %s\n", c.node.port(), c.node.user(), host, string(client.ServerVersion()))
	c.Client = client
	return nil
}

func (c *stdioClient) StartSession() error {
	session, err := c.NewSession()
	if err != nil {
		l.Error(err)
		return err
	}
	defer session.Close()

	modes := gossh.TerminalModes{
		gossh.ECHO:          1,
		gossh.TTY_OP_ISPEED: 14400,
		gossh.TTY_OP_OSPEED: 14400,
	}
	err = session.RequestPty("xterm", c.height, c.width, modes)
	if err != nil {
		l.Error(err)
		return err
	}

	session.Stdout = c.stdout
	session.Stderr = c.stderr
	stdinPipe, err := session.StdinPipe()
	if err != nil {
		l.Error(err)
		return err
	}

	err = session.Shell()
	if err != nil {
		l.Error(err)
		return err
	}

	// then callback
	for i := range c.node.CallbackShells {
		shell := c.node.CallbackShells[i]
		time.Sleep(shell.Delay * time.Millisecond)
		stdinPipe.Write([]byte(shell.Cmd + "\r"))
	}

	// change stdin to user
	go func() {
		_, err = io.Copy(stdinPipe, c.stdin)
		l.Error(err)
		session.Close()
	}()

	// interval get terminal size
	// fix resize issue
	go func() {
		for {
			ch, ok := <-c.winch
			if !ok {
				break
			}

			err = session.WindowChange(ch.Height, ch.Width)
			if err != nil {
				break
			}
		}
	}()

	// send keepalive
	go func() {
		for {
			time.Sleep(time.Second * 10)
			c.SendRequest("keepalive@openssh.com", false, nil)
		}
	}()

	return session.Wait()
}

func (c *defaultClient) Login() error {
	host := c.node.Host
	port := strconv.Itoa(c.node.port())
	jNodes := c.node.Jump

	var client *gossh.Client

	if len(jNodes) > 0 {
		jNode := jNodes[0]
		jc := genSSHConfig(jNode)
		proxyClient, err := gossh.Dial("tcp", net.JoinHostPort(jNode.Host, strconv.Itoa(jNode.port())), jc.clientConfig)
		if err != nil {
			l.Error(err)
			return err
		}
		conn, err := proxyClient.Dial("tcp", net.JoinHostPort(host, port))
		if err != nil {
			l.Error(err)
			return err
		}
		ncc, chans, reqs, err := gossh.NewClientConn(conn, net.JoinHostPort(host, port), c.clientConfig)
		if err != nil {
			l.Error(err)
			return err
		}
		client = gossh.NewClient(ncc, chans, reqs)
	} else {
		client1, err := gossh.Dial("tcp", net.JoinHostPort(host, port), c.clientConfig)
		client = client1
		if err != nil {
			msg := err.Error()
			// use terminal password retry
			if strings.Contains(msg, "no supported methods remain") && !strings.Contains(msg, "password") {
				fmt.Printf("%s@%s's password:", c.clientConfig.User, host)
				var b []byte
				b, err = terminal.ReadPassword(int(syscall.Stdin))
				if err == nil {
					p := string(b)
					if p != "" {
						c.clientConfig.Auth = append(c.clientConfig.Auth, gossh.Password(p))
					}
					fmt.Println()
					client, err = gossh.Dial("tcp", net.JoinHostPort(host, port), c.clientConfig)
				}
			}
		}
		if err != nil {
			l.Error(err)
			return err
		}
	}

	l.Infof("connect server ssh -p %d %s@%s version: %s\n", c.node.port(), c.node.user(), host, string(client.ServerVersion()))
	c.Client = client
	return nil
}

func (c *defaultClient) StartSession() error {
	session, err := c.NewSession()
	if err != nil {
		l.Error(err)
		return err
	}
	defer session.Close()

	fd := int(os.Stdin.Fd())
	state, err := terminal.MakeRaw(fd)
	if err != nil {
		l.Error(err)
		return err
	}
	defer terminal.Restore(fd, state)

	w, h, err := terminal.GetSize(fd)
	if err != nil {
		l.Error(err)
		return err
	}

	modes := gossh.TerminalModes{
		gossh.ECHO:          1,
		gossh.TTY_OP_ISPEED: 14400,
		gossh.TTY_OP_OSPEED: 14400,
	}
	err = session.RequestPty("xterm", h, w, modes)
	if err != nil {
		l.Error(err)
		return err
	}

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	stdinPipe, err := session.StdinPipe()
	if err != nil {
		l.Error(err)
		return err
	}

	err = session.Shell()
	if err != nil {
		l.Error(err)
		return err
	}

	// then callback
	for i := range c.node.CallbackShells {
		shell := c.node.CallbackShells[i]
		time.Sleep(shell.Delay * time.Millisecond)
		stdinPipe.Write([]byte(shell.Cmd + "\r"))
	}

	// change stdin to user
	go func() {
		_, err = io.Copy(stdinPipe, os.Stdin)
		l.Error(err)
		session.Close()
	}()

	// interval get terminal size
	// fix resize issue
	go func() {
		var (
			ow = w
			oh = h
		)
		for {
			cw, ch, err := terminal.GetSize(fd)
			if err != nil {
				break
			}

			if cw != ow || ch != oh {
				err = session.WindowChange(ch, cw)
				if err != nil {
					break
				}
				ow = cw
				oh = ch
			}
			time.Sleep(time.Second)
		}
	}()

	// send keepalive
	go func() {
		for {
			time.Sleep(time.Second * 10)
			c.SendRequest("keepalive@openssh.com", false, nil)
		}
	}()

	return session.Wait()
}
