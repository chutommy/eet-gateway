package wsse

import (
	"fmt"
	"sort"

	"github.com/beevik/etree"
)

const (
	emptyPrefix = ""
	xmlnsPrefix = "xmlns"
)

func excC14NCanonicalize(elem *etree.Element) ([]byte, error) {
	if err := transformExcC14n(elem); err != nil {
		return nil, fmt.Errorf("transform the element (excC14N): %w", err)
	}

	doc := etree.NewDocument()
	doc.SetRoot(elem.Copy())
	doc.WriteSettings = etree.WriteSettings{
		CanonicalAttrVal: true,
		CanonicalEndTags: true,
		CanonicalText:    true,
	}

	canonical, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("write etree document to bytes: %w", err)
	}

	return canonical, nil
}

func transformExcC14n(el *etree.Element) error {
	err := toExcC14n(nsContext{}, nsContext{}, el)
	if err != nil {
		return fmt.Errorf("c14n: %w", err)
	}

	return nil
}

func toExcC14n(ctx, declared nsContext, el *etree.Element) error {
	scope, err := ctx.subContext(el)
	if err != nil {
		return fmt.Errorf("create subcontext: %w", err)
	}

	filteredAttrs := []etree.Attr{}
	utilizedPrefixes := map[string]struct{}{
		el.Space: {},
	}

	for _, attr := range el.Attr {
		if attr.Space != xmlnsPrefix && (attr.Space != emptyPrefix || attr.Key != xmlnsPrefix) {
			if attr.Space != emptyPrefix {
				utilizedPrefixes[attr.Space] = struct{}{}
			}

			filteredAttrs = append(filteredAttrs, attr)
		}
	}

	el.Attr = filteredAttrs
	declared = declared.copy()

	for prefix := range utilizedPrefixes {
		if declaredNamespace, ok := declared.prefixes[prefix]; ok {
			value, ok := scope.prefixes[prefix]
			if ok && declaredNamespace == value {
				continue
			}
		}

		ns := scope.prefixes[prefix]
		// ns, ok := scope.prefixes[prefix]
		// if !ok {
		// 	return fmt.Errorf("undeclared scope prefix: %s", prefix)
		// }

		el.Attr = append(el.Attr, declared.declare(prefix, ns))
	}

	sort.Sort(sortableAttrs(el.Attr))

	for _, child := range el.ChildElements() {
		err := toExcC14n(scope, declared, child)
		if err != nil {
			return fmt.Errorf("canonicalize %s to exc c14n: %w", child.FullTag(), err)
		}
	}

	return nil
}

type nsContext struct {
	prefixes map[string]string
}

func (ctx nsContext) subContext(el *etree.Element) (nsContext, error) {
	nCtx := ctx.copy()

	for _, attr := range el.Attr {
		if attr.Space == xmlnsPrefix {
			nCtx.declare(attr.Key, attr.Value)
		} else if attr.Space == emptyPrefix && attr.Key == xmlnsPrefix {
			nCtx.declare(emptyPrefix, attr.Value)
		}
	}

	return nCtx, nil
}

func (ctx nsContext) copy() nsContext {
	prefixes := make(map[string]string, len(ctx.prefixes)+4)
	for k, v := range ctx.prefixes {
		prefixes[k] = v
	}

	return nsContext{prefixes}
}

func (ctx nsContext) declare(prefix, ns string) etree.Attr {
	ctx.prefixes[prefix] = ns

	if prefix == emptyPrefix {
		return etree.Attr{
			Key:   xmlnsPrefix,
			Value: ns,
		}
	}

	return etree.Attr{
		Space: xmlnsPrefix,
		Key:   prefix,
		Value: ns,
	}
}

type sortableAttrs []etree.Attr

func (a sortableAttrs) Len() int {
	return len(a)
}

func (a sortableAttrs) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a sortableAttrs) Less(i, j int) bool {
	switch {
	case a[j].Space == emptyPrefix && a[j].Key == xmlnsPrefix:
		return false

	case a[i].Space == emptyPrefix && a[i].Key == xmlnsPrefix:
		return true

	case a[i].Space == xmlnsPrefix:
		if a[j].Space == xmlnsPrefix {
			return a[i].Key < a[j].Key
		}
		return true

	case a[j].Space == xmlnsPrefix:
		return false

	case a[i].Space == emptyPrefix:
		if a[j].Space == emptyPrefix {
			return a[i].Key < a[j].Key
		}
		return true

	case a[j].Space == emptyPrefix:
		return false
	}

	return a[i].Space < a[j].Space
}
