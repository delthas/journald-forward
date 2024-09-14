package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/time/rate"
	"gopkg.in/irc.v4"
	"gopkg.in/yaml.v3"
)

type config struct {
	IRCAddress         string                      `yaml:"irc_address"`
	IRCNickname        string                      `yaml:"irc_nickname"`
	IRCUsername        string                      `yaml:"irc_username"`
	IRCPassword        string                      `yaml:"irc_password"`
	IRCChannel         string                      `yaml:"irc_channel"`
	IRCChannelPassword string                      `yaml:"irc_channel_password"`
	Match              []map[string]string         `yaml:"match"`
	MatchParsed        []map[string]*regexp.Regexp `yaml:"-"`
}

type entry map[string][]byte

var c config

var lines = make(chan string, 1024)

func transform(e entry) string {
	if len(c.MatchParsed) == 0 {
		return string(e["MESSAGE"])
	}
outer:
	for i, m := range c.MatchParsed {
		var message []byte
		for k, v := range m {
			if k != "MESSAGE" {
				if !v.Match(e[k]) {
					continue outer
				}
				continue
			}
			s := v.FindSubmatchIndex(e[k])
			if len(s) == 0 {
				continue outer
			}
			if r, ok := c.Match[i]["__REPLACE"]; ok { // Explicit replace: apply from match
				message = v.Expand(nil, []byte(r), e[k], s)
			} else if len(s) > 2 { // Regex groups with no replace: take first group
				message = e[k][s[2]:s[3]]
			} else { // No regex groups: take whole message
				message = e[k][s[0]:s[1]]
			}
		}
		if message == nil { // No message filter
			if r, ok := c.Match[i]["__REPLACE"]; ok { // Explicit (static) replace
				message = []byte(r)
			} else { // No replace: take whole message
				message = e["MESSAGE"]
			}
		}
		return string(message)
	}
	return ""
}

func read() {
	var cursor string
	first := true
	for {
		if first {
			first = false
		} else {
			time.Sleep(1 * time.Second)
		}
		ctx, cancel := context.WithCancel(context.Background())
		var cmd *exec.Cmd
		if cursor == "" {
			cmd = exec.CommandContext(ctx, "journalctl", "-o", "export", "-n", "0", "-f")
		} else {
			cmd = exec.CommandContext(ctx, "journalctl", "-o", "export", "--after-cursor", cursor, "-n", "all", "-f")
		}
		cmd.Stderr = os.Stderr
		r, err := cmd.StdoutPipe()
		if err != nil {
			log.Printf("read: pipe: %v", err)
			continue
		}
		if err := cmd.Start(); err != nil {
			log.Printf("read: run: %v", err)
			continue
		}
		br := bufio.NewReaderSize(r, 16384)
		e := make(entry)
		for {
			l, err := br.ReadString('\n')
			if err != nil {
				log.Printf("read: %v", err)
				break
			}
			l = l[:len(l)-1]
			if l == "" {
				if c := string(e["__CURSOR"]); c != "" {
					cursor = c
				}
				line := transform(e)
				if line != "" {
					select {
					case lines <- line:
					default:
					}
				}
				clear(e)
				continue
			}
			name, value, ok := strings.Cut(l, "=")
			if ok {
				e[name] = []byte(value)
				continue
			}
			length := make([]byte, 8)
			if _, err := io.ReadFull(br, length); err != nil {
				log.Printf("read: %v", err)
				break
			}
			n := binary.LittleEndian.Uint64(length)
			data := make([]byte, n)
			if _, err := io.ReadFull(br, data); err != nil {
				log.Printf("read: %v", err)
				break
			}
			e[name] = data
			if _, err := br.Discard(1); err != nil {
				log.Printf("read: %v", err)
				break
			}
		}
		cancel()
		cmd.Wait()
	}
}

func handle(ctx context.Context, ic *irc.Client, m *irc.Message) {
	switch m.Command {
	case "376", "422": // MOTD: end of connection registration
		if bot, _ := ic.ISupport.GetRaw("BOT"); bot != "" {
			// Advertise self as BOT
			ic.WriteMessage(&irc.Message{
				Command: "MODE",
				Params:  []string{ic.CurrentNick(), "+" + bot},
			})
		}
		r := time.Second
		if rStr, _ := ic.ISupport.GetRaw("RATE"); rStr != "" {
			if rr, err := strconv.Atoi(rStr); err == nil {
				r = time.Duration(rr) * time.Millisecond
			}
		}
		wc := ic.WriteCallback
		limiter := rate.NewLimiter(rate.Every(r), 5)
		ic.WriteCallback = func(w *irc.Writer, line string) error {
			err := limiter.Wait(context.Background())
			if err != nil {
				return err
			}
			return wc(w, line)
		}
		if c.IRCChannelPassword != "" {
			ic.WriteMessage(&irc.Message{
				Command: "JOIN",
				Params:  []string{c.IRCChannel, c.IRCChannelPassword},
			})
		} else {
			ic.WriteMessage(&irc.Message{
				Command: "JOIN",
				Params:  []string{c.IRCChannel},
			})
		}
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case line := <-lines:
					for _, l := range strings.Split(line, "\n") {
						ic.WriteMessage(&irc.Message{
							Command: "PRIVMSG",
							Params:  []string{c.IRCChannel, l},
						})
					}
				}
			}
		}()
	}
}

func write() {
	addr := c.IRCAddress
	if !strings.Contains(addr, "://") {
		addr = "ircs://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil {
		log.Fatalf("parse irc address: %v", err)
	}
	var doTLS bool
	switch u.Scheme {
	case "irc", "ircs", "":
		doTLS = true
	case "irc+insecure":
		doTLS = false
	default:
		log.Fatalf("parse irc address: unknown scheme: %v", u.Scheme)
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		if doTLS {
			u.Host = u.Host + ":6697"
		} else {
			u.Host = u.Host + ":6667"
		}
	}
	first := true
	for {
		if first {
			first = false
		} else {
			time.Sleep(1 * time.Second)
		}
		ctx, cancel := context.WithCancel(context.Background())
		var nc net.Conn
		var err error
		if doTLS {
			nc, err = tls.Dial("tcp", u.Host, nil)
		} else {
			nc, err = net.Dial("tcp", u.Host)
		}
		if err != nil {
			log.Printf("write: dial %v: %v", u.Host, err)
			continue
		}
		ic := irc.NewClient(nc, irc.ClientConfig{
			Nick:           c.IRCNickname,
			Pass:           c.IRCPassword,
			User:           c.IRCUsername,
			Name:           "journald-forward",
			EnableISupport: true,
			PingFrequency:  1 * time.Minute,
			PingTimeout:    15 * time.Second,
			Handler: irc.HandlerFunc(func(c *irc.Client, m *irc.Message) {
				handle(ctx, c, m)
			}),
		})
		if err := ic.RunContext(ctx); err != nil {
			log.Printf("write: %v", err)
		}
		cancel()
	}
}

func main() {
	configPath := flag.String("config", "journald-forward.yaml", "config path")
	flag.Parse()

	f, err := os.Open(*configPath)
	if err != nil {
		log.Fatalf("open config: %v", err)
	}
	err = yaml.NewDecoder(f).Decode(&c)
	f.Close()
	if err != nil {
		log.Fatalf("decode config: %v", err)
	}
	if c.IRCNickname == "" {
		c.IRCNickname = "journald-forward"
	}
	if c.IRCUsername == "" {
		c.IRCUsername = c.IRCNickname
	}
	c.MatchParsed = make([]map[string]*regexp.Regexp, len(c.Match))
	for i, m := range c.Match {
		c.MatchParsed[i] = make(map[string]*regexp.Regexp, len(m))
		for k, v := range m {
			if k == "__REPLACE" {
				continue
			}
			var err error
			c.MatchParsed[i][k], err = regexp.Compile(v)
			if err != nil {
				log.Fatalf("parse config: match %v: %v", v, err)
			}
		}
	}

	go read()
	go write()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}
