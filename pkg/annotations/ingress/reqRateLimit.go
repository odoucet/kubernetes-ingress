package ingress

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/haproxytech/kubernetes-ingress/pkg/annotations/common"
	"github.com/haproxytech/kubernetes-ingress/pkg/haproxy/maps"
	"github.com/haproxytech/kubernetes-ingress/pkg/haproxy/rules"
	"github.com/haproxytech/kubernetes-ingress/pkg/store"
	"github.com/haproxytech/kubernetes-ingress/pkg/utils"
)

type ReqRateLimit struct {
	limit *rules.ReqRateLimit
	track *rules.ReqTrack
	rules *rules.List
	maps  maps.Maps
}

type ReqRateLimitAnn struct {
	parent *ReqRateLimit
	name   string
}

func NewReqRateLimit(r *rules.List, m maps.Maps) *ReqRateLimit {
	return &ReqRateLimit{rules: r, maps: m}
}

func (p *ReqRateLimit) NewAnnotation(n string) ReqRateLimitAnn {
	return ReqRateLimitAnn{
		name:   n,
		parent: p,
	}
}

func (a ReqRateLimitAnn) GetName() string {
	return a.name
}

func (a ReqRateLimitAnn) Process(k store.K8s, annotations ...map[string]string) (err error) {
	input := common.GetValue(a.GetName(), annotations...)
	if input == "" {
		return nil
	}

	switch a.name {
	case "rate-limit-requests":
		// Enable Ratelimiting
		var value int64
		value, err = strconv.ParseInt(input, 10, 64)
		a.parent.limit = &rules.ReqRateLimit{ReqsLimit: value}
		a.parent.track = &rules.ReqTrack{TrackKey: "src"}
		a.parent.rules.Add(a.parent.limit)
		a.parent.rules.Add(a.parent.track)
	case "rate-limit-period":
		if a.parent.limit == nil || a.parent.track == nil {
			return err
		}
		var value *int64
		value, err = utils.ParseTime(input)
		tableName := fmt.Sprintf("RateLimit-%d", *value)
		a.parent.track.TablePeriod = value
		a.parent.track.TableName = tableName
		a.parent.limit.TableName = tableName
	case "rate-limit-size":
		if a.parent.limit == nil || a.parent.track == nil {
			return err
		}
		var value *int64
		value, err = utils.ParseSize(input)
		a.parent.track.TableSize = value
	case "rate-limit-status-code":
		if a.parent.limit == nil || a.parent.track == nil {
			return err
		}
		var value int64
		value, err = utils.ParseInt(input)
		a.parent.limit.DenyStatusCode = value
	case "rate-limit-whitelist":
		if a.parent.limit == nil {
			return err
		}
		// Handle patterns/ prefix for map file references
		if strings.HasPrefix(input, "patterns/") {
			a.parent.limit.WhitelistMap = maps.Path(input)
			return err
		}

		// Create a map for the whitelist
		mapName := maps.Name("ratelimit-whitelist-" + utils.Hash([]byte(input)))
		if !a.parent.maps.MapExists(mapName) {
			for _, address := range strings.Split(input, ",") {
				address = strings.TrimSpace(address)
				if ip := net.ParseIP(address); ip == nil {
					if _, _, err := net.ParseCIDR(address); err != nil {
						return fmt.Errorf("incorrect address '%s' in %s annotation", address, a.name)
					}
				}
				a.parent.maps.MapAppend(mapName, address)
			}
		}
		a.parent.limit.WhitelistMap = maps.GetPath(mapName)
	default:
		err = fmt.Errorf("unknown rate-limit annotation '%s'", a.name)
	}
	return err
}
