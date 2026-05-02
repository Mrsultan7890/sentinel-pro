// ============================================================================
// Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
// Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
//
// Unauthorized copying, distribution, or modification of this software,
// via any medium, is strictly prohibited without written permission.
// ============================================================================

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

type NetworkNode struct {
	ID           string            `json:"id"`
	Type         string            `json:"type"`
	Platform     string            `json:"platform"`
	DisplayName  string            `json:"display_name"`
	Username     string            `json:"username"`
	Followers    int               `json:"followers"`
	Following    int               `json:"following"`
	Verified     bool              `json:"verified"`
	CreatedDate  string            `json:"created_date"`
	LastActive   string            `json:"last_active"`
	Metadata     map[string]string `json:"metadata"`
	RiskScore    float64           `json:"risk_score"`
	Connections  []string          `json:"connections"`
}

type NetworkEdge struct {
	Source       string  `json:"source"`
	Target       string  `json:"target"`
	Relationship string  `json:"relationship"`
	Strength     float64 `json:"strength"`
	FirstSeen    string  `json:"first_seen"`
	LastSeen     string  `json:"last_seen"`
	Evidence     []string `json:"evidence"`
}

type NetworkCluster struct {
	ID          string   `json:"id"`
	Members     []string `json:"members"`
	CenterNode  string   `json:"center_node"`
	Cohesion    float64  `json:"cohesion"`
	Activity    float64  `json:"activity"`
	ThreatLevel string   `json:"threat_level"`
	Purpose     string   `json:"purpose"`
}

type NetworkAnalysis struct {
	Timestamp       time.Time        `json:"timestamp"`
	TotalNodes      int              `json:"total_nodes"`
	TotalEdges      int              `json:"total_edges"`
	Nodes           []NetworkNode    `json:"nodes"`
	Edges           []NetworkEdge    `json:"edges"`
	Clusters        []NetworkCluster `json:"clusters"`
	KeyInfluencers  []string         `json:"key_influencers"`
	SuspiciousNodes []string         `json:"suspicious_nodes"`
	NetworkMetrics  NetworkMetrics   `json:"network_metrics"`
	ThreatAssessment ThreatAssessment `json:"threat_assessment"`
}

type NetworkMetrics struct {
	Density            float64 `json:"density"`
	Centralization     float64 `json:"centralization"`
	AveragePathLength  float64 `json:"average_path_length"`
	ClusteringCoeff    float64 `json:"clustering_coefficient"`
	ComponentCount     int     `json:"component_count"`
	LargestComponent   int     `json:"largest_component"`
}

type ThreatAssessment struct {
	OverallThreatLevel string             `json:"overall_threat_level"`
	CoordinationRisk   float64            `json:"coordination_risk"`
	InfluenceRisk      float64            `json:"influence_risk"`
	PropagationRisk    float64            `json:"propagation_risk"`
	KeyThreats         []ThreatIndicator  `json:"key_threats"`
	Recommendations    []string           `json:"recommendations"`
}

type ThreatIndicator struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
	Nodes       []string `json:"nodes"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: network_mapper <data_file>")
		os.Exit(1)
	}

	dataFile := os.Args[1]
	
	// Read collected data
	data, err := os.ReadFile(dataFile)
	if err != nil {
		log.Fatal("Error reading data file:", err)
	}

	var collectedData []map[string]interface{}
	if err := json.Unmarshal(data, &collectedData); err != nil {
		log.Fatal("Error parsing data JSON:", err)
	}

	mapper := NewNetworkMapper()
	
	// Build network from collected data
	analysis := mapper.BuildNetwork(collectedData)
	
	// Output results
	output, _ := json.MarshalIndent(analysis, "", "  ")
	fmt.Println(string(output))
}

type NetworkMapper struct {
	nodes           map[string]*NetworkNode
	edges           map[string]*NetworkEdge
	mentionPattern  *regexp.Regexp
	urlPattern      *regexp.Regexp
	hashtagPattern  *regexp.Regexp
}

func NewNetworkMapper() *NetworkMapper {
	return &NetworkMapper{
		nodes:          make(map[string]*NetworkNode),
		edges:          make(map[string]*NetworkEdge),
		mentionPattern: regexp.MustCompile(`@([a-zA-Z0-9_]+)`),
		urlPattern:     regexp.MustCompile(`https?://[^\s]+`),
		hashtagPattern: regexp.MustCompile(`#([a-zA-Z0-9_]+)`),
	}
}

func (nm *NetworkMapper) BuildNetwork(data []map[string]interface{}) NetworkAnalysis {
	// Process each data point to extract nodes and relationships
	for _, item := range data {
		nm.processDataItem(item)
	}
	
	// Detect relationships and build edges
	nm.detectRelationships()
	
	// Analyze network structure
	clusters := nm.detectClusters()
	influencers := nm.identifyInfluencers()
	suspicious := nm.identifySuspiciousNodes()
	metrics := nm.calculateNetworkMetrics()
	threatAssessment := nm.assessThreats()
	
	// Convert maps to slices
	nodes := make([]NetworkNode, 0, len(nm.nodes))
	for _, node := range nm.nodes {
		nodes = append(nodes, *node)
	}
	
	edges := make([]NetworkEdge, 0, len(nm.edges))
	for _, edge := range nm.edges {
		edges = append(edges, *edge)
	}
	
	return NetworkAnalysis{
		Timestamp:        time.Now(),
		TotalNodes:       len(nodes),
		TotalEdges:       len(edges),
		Nodes:            nodes,
		Edges:            edges,
		Clusters:         clusters,
		KeyInfluencers:   influencers,
		SuspiciousNodes:  suspicious,
		NetworkMetrics:   metrics,
		ThreatAssessment: threatAssessment,
	}
}

func (nm *NetworkMapper) processDataItem(item map[string]interface{}) {
	source := getString(item, "source")
	platform := getString(item, "platform")
	content := getString(item, "content")
	
	if source == "" {
		return
	}
	
	// Create or update node
	nodeID := fmt.Sprintf("%s_%s", platform, source)
	
	if _, exists := nm.nodes[nodeID]; !exists {
		nm.nodes[nodeID] = &NetworkNode{
			ID:          nodeID,
			Type:        "user",
			Platform:    platform,
			Username:    source,
			DisplayName: getString(item, "display_name"),
			Followers:   getInt(item, "followers"),
			Following:   getInt(item, "following"),
			Verified:    getBool(item, "verified"),
			CreatedDate: getString(item, "created_date"),
			LastActive:  time.Now().Format(time.RFC3339),
			Metadata:    make(map[string]string),
			Connections: make([]string, 0),
		}
	}
	
	node := nm.nodes[nodeID]
	
	// Update node metadata
	if bio := getString(item, "bio"); bio != "" {
		node.Metadata["bio"] = bio
	}
	if location := getString(item, "location"); location != "" {
		node.Metadata["location"] = location
	}
	if website := getString(item, "website"); website != "" {
		node.Metadata["website"] = website
	}
	
	// Calculate risk score based on content and metadata
	node.RiskScore = nm.calculateNodeRiskScore(node, content)
	
	// Extract mentions and relationships from content
	nm.extractMentionsFromContent(nodeID, content)
}

func (nm *NetworkMapper) extractMentionsFromContent(sourceNodeID, content string) {
	// Extract @mentions
	mentions := nm.mentionPattern.FindAllStringSubmatch(content, -1)
	for _, mention := range mentions {
		if len(mention) > 1 {
			mentionedUser := mention[1]
			nm.addMentionRelationship(sourceNodeID, mentionedUser, "mention")
		}
	}
	
	// Extract hashtags for topic clustering
	hashtags := nm.hashtagPattern.FindAllStringSubmatch(content, -1)
	for _, hashtag := range hashtags {
		if len(hashtag) > 1 {
			hashtagText := hashtag[1]
			nm.addTopicRelationship(sourceNodeID, hashtagText)
		}
	}
}

func (nm *NetworkMapper) addMentionRelationship(sourceID, targetUsername, relType string) {
	// Find or create target node
	var targetID string
	for id, node := range nm.nodes {
		if strings.Contains(node.Username, targetUsername) {
			targetID = id
			break
		}
	}
	
	if targetID == "" {
		// Create placeholder node for mentioned user
		targetID = fmt.Sprintf("unknown_%s", targetUsername)
		nm.nodes[targetID] = &NetworkNode{
			ID:          targetID,
			Type:        "mentioned_user",
			Platform:    "unknown",
			Username:    targetUsername,
			DisplayName: targetUsername,
			LastActive:  time.Now().Format(time.RFC3339),
			Metadata:    make(map[string]string),
			Connections: make([]string, 0),
		}
	}
	
	// Create edge
	edgeID := fmt.Sprintf("%s_%s_%s", sourceID, targetID, relType)
	if _, exists := nm.edges[edgeID]; !exists {
		nm.edges[edgeID] = &NetworkEdge{
			Source:       sourceID,
			Target:       targetID,
			Relationship: relType,
			Strength:     1.0,
			FirstSeen:    time.Now().Format(time.RFC3339),
			LastSeen:     time.Now().Format(time.RFC3339),
			Evidence:     []string{"content_mention"},
		}
	} else {
		// Strengthen existing relationship
		nm.edges[edgeID].Strength += 0.5
		nm.edges[edgeID].LastSeen = time.Now().Format(time.RFC3339)
	}
	
	// Update node connections
	nm.nodes[sourceID].Connections = append(nm.nodes[sourceID].Connections, targetID)
	nm.nodes[targetID].Connections = append(nm.nodes[targetID].Connections, sourceID)
}

func (nm *NetworkMapper) addTopicRelationship(nodeID, topic string) {
	// Store topic relationships for clustering
	if nm.nodes[nodeID].Metadata == nil {
		nm.nodes[nodeID].Metadata = make(map[string]string)
	}
	
	topics := nm.nodes[nodeID].Metadata["topics"]
	if topics == "" {
		nm.nodes[nodeID].Metadata["topics"] = topic
	} else {
		nm.nodes[nodeID].Metadata["topics"] = topics + "," + topic
	}
}

func (nm *NetworkMapper) detectRelationships() {
	// Detect additional relationships based on patterns
	
	// Same platform clustering
	platformGroups := make(map[string][]string)
	for id, node := range nm.nodes {
		platformGroups[node.Platform] = append(platformGroups[node.Platform], id)
	}
	
	// Create weak connections between users on same platform with similar topics
	for platform, nodeIDs := range platformGroups {
		if len(nodeIDs) > 1 {
			nm.createTopicBasedConnections(nodeIDs, platform)
		}
	}
}

func (nm *NetworkMapper) createTopicBasedConnections(nodeIDs []string, platform string) {
	for i, nodeID1 := range nodeIDs {
		for j, nodeID2 := range nodeIDs {
			if i >= j {
				continue
			}
			
			node1 := nm.nodes[nodeID1]
			node2 := nm.nodes[nodeID2]
			
			// Check for topic similarity
			topics1 := strings.Split(node1.Metadata["topics"], ",")
			topics2 := strings.Split(node2.Metadata["topics"], ",")
			
			commonTopics := nm.findCommonTopics(topics1, topics2)
			if len(commonTopics) >= 2 {
				// Create weak topic-based connection
				edgeID := fmt.Sprintf("%s_%s_topic", nodeID1, nodeID2)
				if _, exists := nm.edges[edgeID]; !exists {
					nm.edges[edgeID] = &NetworkEdge{
						Source:       nodeID1,
						Target:       nodeID2,
						Relationship: "topic_similarity",
						Strength:     float64(len(commonTopics)) * 0.3,
						FirstSeen:    time.Now().Format(time.RFC3339),
						LastSeen:     time.Now().Format(time.RFC3339),
						Evidence:     commonTopics,
					}
				}
			}
		}
	}
}

func (nm *NetworkMapper) findCommonTopics(topics1, topics2 []string) []string {
	topicSet := make(map[string]bool)
	for _, topic := range topics1 {
		if topic != "" {
			topicSet[strings.ToLower(strings.TrimSpace(topic))] = true
		}
	}
	
	var common []string
	for _, topic := range topics2 {
		cleanTopic := strings.ToLower(strings.TrimSpace(topic))
		if cleanTopic != "" && topicSet[cleanTopic] {
			common = append(common, cleanTopic)
		}
	}
	
	return common
}

func (nm *NetworkMapper) calculateNodeRiskScore(node *NetworkNode, content string) float64 {
	score := 0.0
	
	// High follower count with low following (potential bot/influence account)
	if node.Followers > 1000 && node.Following < 100 {
		score += 0.2
	}
	
	// Verified accounts get lower risk
	if node.Verified {
		score -= 0.1
	}
	
	// Recent account creation
	if node.CreatedDate != "" {
		// Simplified: assume recent if no specific date parsing
		score += 0.1
	}
	
	// Content-based risk factors
	content = strings.ToLower(content)
	riskKeywords := []string{
		"attack", "bomb", "kill", "destroy", "eliminate", "target",
		"conspiracy", "fake news", "deep state", "revolution", "uprising",
	}
	
	for _, keyword := range riskKeywords {
		if strings.Contains(content, keyword) {
			score += 0.15
		}
	}
	
	// Excessive posting (simplified check)
	if len(content) > 5000 {
		score += 0.1
	}
	
	return min(score, 1.0)
}

func (nm *NetworkMapper) detectClusters() []NetworkCluster {
	var clusters []NetworkCluster
	
	// Simple clustering based on connection density
	visited := make(map[string]bool)
	clusterID := 0
	
	for nodeID := range nm.nodes {
		if visited[nodeID] {
			continue
		}
		
		cluster := nm.exploreCluster(nodeID, visited)
		if len(cluster) >= 3 { // Minimum cluster size
			clusterID++
			
			centerNode := nm.findClusterCenter(cluster)
			cohesion := nm.calculateClusterCohesion(cluster)
			activity := nm.calculateClusterActivity(cluster)
			threatLevel := nm.assessClusterThreat(cluster)
			purpose := nm.identifyClusterPurpose(cluster)
			
			clusters = append(clusters, NetworkCluster{
				ID:          fmt.Sprintf("cluster_%d", clusterID),
				Members:     cluster,
				CenterNode:  centerNode,
				Cohesion:    cohesion,
				Activity:    activity,
				ThreatLevel: threatLevel,
				Purpose:     purpose,
			})
		}
	}
	
	return clusters
}

func (nm *NetworkMapper) exploreCluster(startNode string, visited map[string]bool) []string {
	cluster := []string{startNode}
	visited[startNode] = true
	
	// BFS to find connected nodes
	queue := []string{startNode}
	
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		
		for _, connection := range nm.nodes[current].Connections {
			if !visited[connection] {
				visited[connection] = true
				cluster = append(cluster, connection)
				queue = append(queue, connection)
			}
		}
	}
	
	return cluster
}

func (nm *NetworkMapper) findClusterCenter(cluster []string) string {
	maxConnections := 0
	centerNode := cluster[0]
	
	for _, nodeID := range cluster {
		connections := len(nm.nodes[nodeID].Connections)
		if connections > maxConnections {
			maxConnections = connections
			centerNode = nodeID
		}
	}
	
	return centerNode
}

func (nm *NetworkMapper) calculateClusterCohesion(cluster []string) float64 {
	if len(cluster) < 2 {
		return 0.0
	}
	
	totalPossibleEdges := len(cluster) * (len(cluster) - 1) / 2
	actualEdges := 0
	
	for i, node1 := range cluster {
		for j, node2 := range cluster {
			if i >= j {
				continue
			}
			
			edgeID1 := fmt.Sprintf("%s_%s_mention", node1, node2)
			edgeID2 := fmt.Sprintf("%s_%s_mention", node2, node1)
			edgeID3 := fmt.Sprintf("%s_%s_topic", node1, node2)
			
			if _, exists := nm.edges[edgeID1]; exists {
				actualEdges++
			} else if _, exists := nm.edges[edgeID2]; exists {
				actualEdges++
			} else if _, exists := nm.edges[edgeID3]; exists {
				actualEdges++
			}
		}
	}
	
	return float64(actualEdges) / float64(totalPossibleEdges)
}

func (nm *NetworkMapper) calculateClusterActivity(cluster []string) float64 {
	totalRisk := 0.0
	for _, nodeID := range cluster {
		totalRisk += nm.nodes[nodeID].RiskScore
	}
	return totalRisk / float64(len(cluster))
}

func (nm *NetworkMapper) assessClusterThreat(cluster []string) string {
	avgActivity := nm.calculateClusterActivity(cluster)
	cohesion := nm.calculateClusterCohesion(cluster)
	
	threatScore := (avgActivity + cohesion) / 2.0
	
	if threatScore >= 0.8 {
		return "CRITICAL"
	} else if threatScore >= 0.6 {
		return "HIGH"
	} else if threatScore >= 0.4 {
		return "MEDIUM"
	} else if threatScore >= 0.2 {
		return "LOW"
	}
	return "MINIMAL"
}

func (nm *NetworkMapper) identifyClusterPurpose(cluster []string) string {
	// Analyze common topics and patterns
	topicCounts := make(map[string]int)
	
	for _, nodeID := range cluster {
		topics := nm.nodes[nodeID].Metadata["topics"]
		if topics != "" {
			for _, topic := range strings.Split(topics, ",") {
				topic = strings.TrimSpace(topic)
				if topic != "" {
					topicCounts[topic]++
				}
			}
		}
	}
	
	// Find most common topic
	maxCount := 0
	dominantTopic := "unknown"
	
	for topic, count := range topicCounts {
		if count > maxCount {
			maxCount = count
			dominantTopic = topic
		}
	}
	
	if maxCount >= len(cluster)/2 {
		return fmt.Sprintf("Topic coordination: %s", dominantTopic)
	}
	
	return "General coordination"
}

func (nm *NetworkMapper) identifyInfluencers() []string {
	type nodeScore struct {
		id    string
		score float64
	}
	
	var scores []nodeScore
	
	for id, node := range nm.nodes {
		// Calculate influence score based on connections and followers
		connectionScore := float64(len(node.Connections)) / 10.0
		followerScore := float64(node.Followers) / 10000.0
		
		influence := connectionScore + followerScore
		if node.Verified {
			influence += 0.2
		}
		
		scores = append(scores, nodeScore{id: id, score: influence})
	}
	
	// Sort by influence score
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].score > scores[j].score
	})
	
	// Return top influencers
	var influencers []string
	maxInfluencers := 5
	if len(scores) < maxInfluencers {
		maxInfluencers = len(scores)
	}
	
	for i := 0; i < maxInfluencers; i++ {
		if scores[i].score > 0.5 { // Minimum influence threshold
			influencers = append(influencers, scores[i].id)
		}
	}
	
	return influencers
}

func (nm *NetworkMapper) identifySuspiciousNodes() []string {
	var suspicious []string
	
	for id, node := range nm.nodes {
		if node.RiskScore > 0.6 {
			suspicious = append(suspicious, id)
		}
	}
	
	return suspicious
}

func (nm *NetworkMapper) calculateNetworkMetrics() NetworkMetrics {
	nodeCount := len(nm.nodes)
	edgeCount := len(nm.edges)
	
	// Calculate density
	maxPossibleEdges := nodeCount * (nodeCount - 1) / 2
	density := 0.0
	if maxPossibleEdges > 0 {
		density = float64(edgeCount) / float64(maxPossibleEdges)
	}
	
	// Simple metrics (more complex calculations would require graph algorithms)
	return NetworkMetrics{
		Density:           density,
		Centralization:    nm.calculateCentralization(),
		AveragePathLength: 2.5, // Placeholder
		ClusteringCoeff:   density * 0.8, // Approximation
		ComponentCount:    nm.countComponents(),
		LargestComponent:  nm.findLargestComponent(),
	}
}

func (nm *NetworkMapper) calculateCentralization() float64 {
	if len(nm.nodes) == 0 {
		return 0.0
	}
	
	maxConnections := 0
	totalConnections := 0
	
	for _, node := range nm.nodes {
		connections := len(node.Connections)
		totalConnections += connections
		if connections > maxConnections {
			maxConnections = connections
		}
	}
	
	avgConnections := float64(totalConnections) / float64(len(nm.nodes))
	return float64(maxConnections) / (avgConnections + 1.0)
}

func (nm *NetworkMapper) countComponents() int {
	visited := make(map[string]bool)
	components := 0
	
	for nodeID := range nm.nodes {
		if !visited[nodeID] {
			nm.exploreComponent(nodeID, visited)
			components++
		}
	}
	
	return components
}

func (nm *NetworkMapper) exploreComponent(startNode string, visited map[string]bool) {
	visited[startNode] = true
	
	for _, connection := range nm.nodes[startNode].Connections {
		if !visited[connection] {
			nm.exploreComponent(connection, visited)
		}
	}
}

func (nm *NetworkMapper) findLargestComponent() int {
	visited := make(map[string]bool)
	largestSize := 0
	
	for nodeID := range nm.nodes {
		if !visited[nodeID] {
			component := nm.exploreCluster(nodeID, visited)
			if len(component) > largestSize {
				largestSize = len(component)
			}
		}
	}
	
	return largestSize
}

func (nm *NetworkMapper) assessThreats() ThreatAssessment {
	// Calculate various risk metrics
	coordinationRisk := nm.calculateCoordinationRisk()
	influenceRisk := nm.calculateInfluenceRisk()
	propagationRisk := nm.calculatePropagationRisk()
	
	overallThreat := (coordinationRisk + influenceRisk + propagationRisk) / 3.0
	
	threatLevel := "LOW"
	if overallThreat >= 0.8 {
		threatLevel = "CRITICAL"
	} else if overallThreat >= 0.6 {
		threatLevel = "HIGH"
	} else if overallThreat >= 0.4 {
		threatLevel = "MEDIUM"
	}
	
	keyThreats := nm.identifyKeyThreats()
	recommendations := nm.generateThreatRecommendations(overallThreat, keyThreats)
	
	return ThreatAssessment{
		OverallThreatLevel: threatLevel,
		CoordinationRisk:   coordinationRisk,
		InfluenceRisk:      influenceRisk,
		PropagationRisk:    propagationRisk,
		KeyThreats:         keyThreats,
		Recommendations:    recommendations,
	}
}

func (nm *NetworkMapper) calculateCoordinationRisk() float64 {
	highRiskNodes := 0
	totalNodes := len(nm.nodes)
	
	for _, node := range nm.nodes {
		if node.RiskScore > 0.6 {
			highRiskNodes++
		}
	}
	
	if totalNodes == 0 {
		return 0.0
	}
	
	return float64(highRiskNodes) / float64(totalNodes)
}

func (nm *NetworkMapper) calculateInfluenceRisk() float64 {
	totalInfluence := 0.0
	nodeCount := 0
	
	for _, node := range nm.nodes {
		influence := float64(node.Followers)/1000.0 + float64(len(node.Connections))/10.0
		if node.Verified {
			influence += 0.2
		}
		totalInfluence += influence * node.RiskScore
		nodeCount++
	}
	
	if nodeCount == 0 {
		return 0.0
	}
	
	if totalInfluence/float64(nodeCount) < 1.0 {
		return totalInfluence/float64(nodeCount)
	}
	return 1.0
}

func (nm *NetworkMapper) calculatePropagationRisk() float64 {
	// Based on network density and high-risk node connectivity
	metrics := nm.calculateNetworkMetrics()
	highRiskConnectivity := 0.0
	
	for _, node := range nm.nodes {
		if node.RiskScore > 0.6 {
			highRiskConnectivity += float64(len(node.Connections))
		}
	}
	
	result := metrics.Density + highRiskConnectivity/100.0
	if result < 1.0 {
		return result
	}
	return 1.0
}

func (nm *NetworkMapper) identifyKeyThreats() []ThreatIndicator {
	var threats []ThreatIndicator
	
	// High-risk clusters
	clusters := nm.detectClusters()
	for _, cluster := range clusters {
		if cluster.ThreatLevel == "CRITICAL" || cluster.ThreatLevel == "HIGH" {
			threats = append(threats, ThreatIndicator{
				Type:        "Coordinated Network",
				Description: fmt.Sprintf("High-risk cluster with %d members: %s", len(cluster.Members), cluster.Purpose),
				Severity:    cluster.ThreatLevel,
				Confidence:  cluster.Cohesion,
				Nodes:       cluster.Members,
			})
		}
	}
	
	// High-influence, high-risk nodes
	for id, node := range nm.nodes {
		if node.RiskScore > 0.7 && (node.Followers > 1000 || len(node.Connections) > 10) {
			threats = append(threats, ThreatIndicator{
				Type:        "High-Risk Influencer",
				Description: fmt.Sprintf("High-risk account with significant reach: %s", node.Username),
				Severity:    "HIGH",
				Confidence:  node.RiskScore,
				Nodes:       []string{id},
			})
		}
	}
	
	return threats
}

func (nm *NetworkMapper) generateThreatRecommendations(overallThreat float64, threats []ThreatIndicator) []string {
	var recommendations []string
	
	if overallThreat >= 0.7 {
		recommendations = append(recommendations, "IMMEDIATE: Network shows critical threat indicators - escalate to law enforcement")
		recommendations = append(recommendations, "Implement enhanced monitoring of all identified nodes")
		recommendations = append(recommendations, "Document network structure for legal proceedings")
	}
	
	if len(threats) > 0 {
		recommendations = append(recommendations, fmt.Sprintf("Focus investigation on %d identified threat indicators", len(threats)))
	}
	
	// Cluster-specific recommendations
	clusters := nm.detectClusters()
	highRiskClusters := 0
	for _, cluster := range clusters {
		if cluster.ThreatLevel == "CRITICAL" || cluster.ThreatLevel == "HIGH" {
			highRiskClusters++
		}
	}
	
	if highRiskClusters > 0 {
		recommendations = append(recommendations, fmt.Sprintf("Monitor %d high-risk coordination clusters for escalation", highRiskClusters))
	}
	
	return recommendations
}

// Helper functions
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if val, ok := m[key]; ok {
		if num, ok := val.(float64); ok {
			return int(num)
		}
		if num, ok := val.(int); ok {
			return num
		}
	}
	return 0
}

func getBool(m map[string]interface{}, key string) bool {
	if val, ok := m[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}