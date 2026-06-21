#!/usr/bin/env python3
"""
Enhanced Analysis Helper Functions
Generates detailed insights from collected OSINT data
"""

def generate_profile_insights(social_data):
    """Generate insights from profile data"""
    insights = []
    
    if not social_data:
        return insights
    
    # Count verified profiles
    verified_count = sum(1 for p in social_data if p.get('profile_info', {}).get('verified', False))
    if verified_count > 0:
        insights.append(f"[green]✓[/green] {verified_count} verified profile(s) found - likely authentic identity")
    
    # Check creation dates
    recent_accounts = 0
    for profile in social_data:
        creation_date = profile.get('profile_info', {}).get('creation_date', 'N/A')
        if creation_date != 'N/A' and ('2023' in creation_date or '2024' in creation_date or '2025' in creation_date or '2026' in creation_date):
            recent_accounts += 1
    
    if recent_accounts > 2:
        insights.append(f"[yellow]⚠[/yellow] {recent_accounts} recently created accounts detected - monitor for suspicious activity")
    
    # Follower analysis
    high_follower_profiles = []
    for profile in social_data:
        followers = profile.get('profile_info', {}).get('follower_count', 'N/A')
        if followers != 'N/A':
            # Convert K, M to numbers
            if 'K' in str(followers):
                num = float(str(followers).replace('K', '').replace(',', '')) * 1000
            elif 'M' in str(followers):
                num = float(str(followers).replace('M', '').replace(',', '')) * 1000000
            else:
                try:
                    num = float(str(followers).replace(',', ''))
                except:
                    num = 0
            
            if num > 10000:
                high_follower_profiles.append((profile.get('platform', 'unknown'), followers))
    
    if high_follower_profiles:
        platforms_str = ', '.join([f"{p[0]} ({p[1]})" for p in high_follower_profiles])
        insights.append(f"[cyan]🌟[/cyan] High influence detected on: {platforms_str}")
    
    # Contact info found
    contact_found = False
    for profile in social_data:
        contact = profile.get('contact_info', {})
        if contact.get('email') or contact.get('phone'):
            contact_found = True
            break
    
    if contact_found:
        insights.append("[red]📧[/red] Contact information publicly exposed - privacy concern")
    
    return insights


def generate_content_insights(social_data):
    """Generate insights from content analysis"""
    insights = []
    
    # Hashtag analysis
    all_hashtags = []
    for profile in social_data:
        bio_hashtags = profile.get('bio_data', {}).get('hashtags', [])
        post_hashtags = profile.get('posts_data', {}).get('recent_hashtags', [])
        all_hashtags.extend(bio_hashtags)
        all_hashtags.extend(post_hashtags)
    
    if all_hashtags:
        unique_hashtags = list(set(all_hashtags))
        if len(unique_hashtags) > 10:
            top_hashtags = ', '.join([f"#{h}" for h in unique_hashtags[:5]])
            insights.append(f"[magenta]#[/magenta] Active hashtag user - Top tags: {top_hashtags}")
    
    # Mention analysis
    all_mentions = []
    for profile in social_data:
        bio_mentions = profile.get('bio_data', {}).get('mentions', [])
        post_mentions = profile.get('posts_data', {}).get('recent_mentions', [])
        all_mentions.extend(bio_mentions)
        all_mentions.extend(post_mentions)
    
    if all_mentions:
        unique_mentions = list(set(all_mentions))
        if len(unique_mentions) > 5:
            insights.append(f"[cyan]@[/cyan] Highly connected - {len(unique_mentions)} unique mentions found")
    
    # Post activity
    total_posts_found = sum(len(p.get('posts_data', {}).get('posts', [])) for p in social_data)
    if total_posts_found > 10:
        insights.append(f"[green]📊[/green] High activity - {total_posts_found} posts collected across platforms")
    elif total_posts_found == 0:
        insights.append("[yellow]⚠[/yellow] Low activity - no recent posts found (inactive or private)")
    
    # Bio analysis
    locations = []
    websites = []
    for profile in social_data:
        bio = profile.get('bio_data', {})
        if bio.get('location'):
            locations.append(bio['location'])
        if bio.get('website'):
            websites.append(bio['website'])
    
    if locations:
        unique_locations = list(set(locations))
        if len(unique_locations) > 1:
            insights.append(f"[blue]🌍[/blue] Multiple locations mentioned: {', '.join(unique_locations[:3])}")
        else:
            insights.append(f"[blue]📍[/blue] Location: {unique_locations[0]}")
    
    if websites:
        insights.append(f"[green]🔗[/green] {len(set(websites))} external link(s) in profiles")
    
    return insights


def generate_network_insights(social_data):
    """Generate insights from network analysis"""
    insights = []
    
    # Platform diversity
    platforms = [p.get('platform', 'unknown') for p in social_data if p.get('status') == 'success']
    unique_platforms = list(set(platforms))
    
    if len(unique_platforms) >= 5:
        insights.append(f"[cyan]🌐[/cyan] Multi-platform presence - active on {len(unique_platforms)} platforms")
    elif len(unique_platforms) == 1:
        insights.append(f"[yellow]⚠[/yellow] Single platform presence - limited digital footprint")
    
    # Professional vs Personal
    professional_platforms = ['linkedin', 'github', 'stackoverflow', 'behance', 'dribbble']
    personal_platforms = ['instagram', 'facebook', 'twitter', 'tiktok', 'snapchat']
    
    prof_count = sum(1 for p in platforms if p in professional_platforms)
    pers_count = sum(1 for p in platforms if p in personal_platforms)
    
    if prof_count > 0 and pers_count > 0:
        insights.append(f"[blue]💼[/blue] Mixed presence - {prof_count} professional, {pers_count} personal platforms")
    elif prof_count > pers_count:
        insights.append("[blue]💼[/blue] Primarily professional presence - business/tech focused")
    elif pers_count > prof_count:
        insights.append("[green]👥[/green] Primarily personal presence - social/entertainment focused")
    
    # Cross-platform username consistency
    usernames = []
    for profile in social_data:
        username = profile.get('profile_info', {}).get('username', '')
        if username and username != 'N/A':
            usernames.append(username.lower())
    
    if len(set(usernames)) == 1 and len(usernames) > 1:
        insights.append(f"[green]✓[/green] Consistent username across platforms - strong identity coherence")
    elif len(set(usernames)) > 1:
        insights.append(f"[yellow]⚠[/yellow] Multiple usernames detected - {len(set(usernames))} variations found")
    
    return insights
