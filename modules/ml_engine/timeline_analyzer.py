"""
Timeline Analyzer - Activity Pattern Analysis
OSINT Intelligence Grade: Kab active rehta hai, kya pattern hai
No API key needed — pure ML/statistics
"""

import re
import logging
import numpy as np
from collections import Counter, defaultdict
from datetime import datetime, timezone
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

# Timezone offset hints from text
TIMEZONE_HINTS = {
    'IST':  5.5,  'PKT': 5.0,  'BST': 6.0,  'NPT': 5.75,
    'PST': -8.0,  'PDT': -7.0, 'EST': -5.0,  'EDT': -4.0,
    'CST': -6.0,  'MST': -7.0, 'GMT':  0.0,  'UTC':  0.0,
    'CET':  1.0,  'EET':  2.0, 'MSK':  3.0,  'GST':  4.0,
    'SGT':  8.0,  'JST':  9.0, 'AEST':10.0,  'NZST':12.0,
}

ACTIVITY_LABELS = {
    (0,  6):  'late_night',
    (6,  9):  'early_morning',
    (9,  12): 'morning',
    (12, 14): 'midday',
    (14, 17): 'afternoon',
    (17, 20): 'evening',
    (20, 24): 'night',
}


class TimelineAnalyzer:
    """
    Post timestamps aur activity patterns se:
    1. Active hours detect karo (kab online rehta hai)
    2. Timezone estimate karo
    3. Posting frequency analyze karo
    4. Behavioral patterns dhundho (burst posting, dormancy, etc.)
    5. KMeans se activity clusters banao
    """

    def analyze(self, timestamps: list, texts: list = None) -> dict:
        """
        timestamps: list of datetime strings or datetime objects
        texts: optional list of post texts (for content-time correlation)
        """
        if not timestamps:
            return self._empty_result()

        # Parse timestamps
        parsed = self._parse_timestamps(timestamps)
        if not parsed:
            return self._empty_result()

        result = {
            'total_posts':        len(parsed),
            'date_range':         self._date_range(parsed),
            'active_hours':       self._analyze_active_hours(parsed),
            'active_days':        self._analyze_active_days(parsed),
            'posting_frequency':  self._analyze_frequency(parsed),
            'timezone_estimate':  self._estimate_timezone(parsed),
            'activity_clusters':  self._cluster_activity(parsed),
            'behavioral_patterns':self._detect_behavioral_patterns(parsed),
            'content_time_corr':  self._content_time_correlation(parsed, texts) if texts else {},
            'osint_insights':     [],
        }

        result['osint_insights'] = self._generate_insights(result)
        return result

    # ── Timestamp Parsing ──────────────────────────────────────────────────────

    def _parse_timestamps(self, timestamps: list) -> list:
        """Various timestamp formats ko datetime objects mein convert karo"""
        parsed = []
        formats = [
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d',
            '%d/%m/%Y %H:%M',
            '%B %d, %Y',
        ]

        for ts in timestamps:
            if isinstance(ts, datetime):
                parsed.append(ts)
                continue
            if not isinstance(ts, str):
                continue

            # Unix timestamp
            if re.match(r'^\d{10}$', ts.strip()):
                try:
                    parsed.append(datetime.fromtimestamp(int(ts)))
                    continue
                except Exception:
                    pass

            # Try each format
            for fmt in formats:
                try:
                    parsed.append(datetime.strptime(ts.strip()[:19], fmt))
                    break
                except ValueError:
                    continue

        return sorted(parsed)

    # ── Active Hours Analysis ──────────────────────────────────────────────────

    def _analyze_active_hours(self, timestamps: list) -> dict:
        """Kaunse hours mein sabse zyada active hai"""
        hour_counts = Counter(dt.hour for dt in timestamps)

        # Normalize to percentage
        total = len(timestamps)
        hour_dist = {h: round(hour_counts.get(h, 0) / total * 100, 1) for h in range(24)}

        # Peak hours (top 3)
        peak_hours = sorted(hour_counts.items(), key=lambda x: x[1], reverse=True)[:3]

        # Activity label for peak time
        peak_hour = peak_hours[0][0] if peak_hours else 12
        activity_label = 'unknown'
        for (start, end), label in ACTIVITY_LABELS.items():
            if start <= peak_hour < end:
                activity_label = label
                break

        # Sleep window estimate (least active 6-hour window)
        sleep_window = self._find_sleep_window(hour_counts)

        return {
            'distribution':   hour_dist,
            'peak_hours':     [{'hour': h, 'count': c, 'label': self._hour_label(h)} for h, c in peak_hours],
            'primary_activity': activity_label,
            'sleep_window':   sleep_window,
            'night_owl':      peak_hour >= 22 or peak_hour <= 3,
            'early_bird':     6 <= peak_hour <= 8,
        }

    def _find_sleep_window(self, hour_counts: Counter) -> dict:
        """Sabse kam active 6-hour window = likely sleep time"""
        min_activity = float('inf')
        sleep_start  = 0

        for start in range(24):
            window_count = sum(hour_counts.get((start + i) % 24, 0) for i in range(6))
            if window_count < min_activity:
                min_activity = window_count
                sleep_start  = start

        sleep_end = (sleep_start + 6) % 24
        return {
            'estimated_start': sleep_start,
            'estimated_end':   sleep_end,
            'label':           f"{sleep_start:02d}:00 - {sleep_end:02d}:00",
        }

    def _hour_label(self, hour: int) -> str:
        for (start, end), label in ACTIVITY_LABELS.items():
            if start <= hour < end:
                return label
        return 'unknown'

    # ── Active Days Analysis ───────────────────────────────────────────────────

    def _analyze_active_days(self, timestamps: list) -> dict:
        """Kaunse days mein zyada active hai"""
        day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        day_counts = Counter(dt.weekday() for dt in timestamps)

        total = len(timestamps)
        day_dist = {day_names[d]: round(day_counts.get(d, 0) / total * 100, 1) for d in range(7)}

        peak_day_idx = max(day_counts, key=day_counts.get) if day_counts else 0
        peak_day     = day_names[peak_day_idx]

        weekend_activity = sum(day_counts.get(d, 0) for d in [5, 6]) / total * 100
        weekday_activity = 100 - weekend_activity

        return {
            'distribution':    day_dist,
            'peak_day':        peak_day,
            'weekend_pct':     round(weekend_activity, 1),
            'weekday_pct':     round(weekday_activity, 1),
            'pattern':         'weekend_active' if weekend_activity > 40 else 'weekday_active',
        }

    # ── Posting Frequency ─────────────────────────────────────────────────────

    def _analyze_frequency(self, timestamps: list) -> dict:
        """Posting frequency aur gaps analyze karo"""
        if len(timestamps) < 2:
            return {'avg_posts_per_day': 0, 'pattern': 'insufficient_data'}

        # Time span
        span_days = (timestamps[-1] - timestamps[0]).days or 1
        avg_per_day = len(timestamps) / span_days

        # Inter-post gaps (in hours)
        gaps = []
        for i in range(1, len(timestamps)):
            gap_hours = (timestamps[i] - timestamps[i-1]).total_seconds() / 3600
            gaps.append(gap_hours)

        avg_gap   = np.mean(gaps)
        median_gap = np.median(gaps)
        max_gap   = max(gaps)
        min_gap   = min(gaps)

        # Burst detection (many posts in short time)
        burst_threshold = avg_gap * 0.1
        bursts = sum(1 for g in gaps if g < burst_threshold)

        # Dormancy periods (very long gaps)
        dormancy_threshold = avg_gap * 5
        dormancies = [(i, gaps[i]) for i in range(len(gaps)) if gaps[i] > dormancy_threshold]

        return {
            'avg_posts_per_day':  round(avg_per_day, 2),
            'avg_gap_hours':      round(float(avg_gap), 2),
            'median_gap_hours':   round(float(median_gap), 2),
            'max_gap_hours':      round(float(max_gap), 2),
            'min_gap_hours':      round(float(min_gap), 4),
            'burst_count':        bursts,
            'dormancy_periods':   len(dormancies),
            'pattern':            self._frequency_pattern(avg_per_day, bursts),
        }

    def _frequency_pattern(self, avg_per_day: float, bursts: int) -> str:
        if avg_per_day > 10:
            return 'very_high_activity'
        elif avg_per_day > 3:
            return 'high_activity'
        elif avg_per_day > 1:
            return 'moderate_activity'
        elif avg_per_day > 0.3:
            return 'low_activity'
        else:
            return 'sporadic'

    # ── Timezone Estimation ────────────────────────────────────────────────────

    def _estimate_timezone(self, timestamps: list) -> dict:
        """
        Activity pattern se timezone estimate karo.
        Assumption: Most people are active 8am-11pm local time.
        Peak activity hour → likely local time → timezone offset
        """
        if not timestamps:
            return {'estimated_offset': None, 'confidence': 0}

        hour_counts = Counter(dt.hour for dt in timestamps)
        peak_hour   = max(hour_counts, key=hour_counts.get)

        # Assume peak activity is around 8pm local time (20:00)
        # offset = local_peak - utc_peak
        assumed_local_peak = 20
        estimated_offset   = assumed_local_peak - peak_hour

        # Normalize to -12 to +14
        if estimated_offset > 14:
            estimated_offset -= 24
        elif estimated_offset < -12:
            estimated_offset += 24

        # Find closest known timezone
        closest_tz = min(TIMEZONE_HINTS.items(), key=lambda x: abs(x[1] - estimated_offset))

        # Confidence based on how concentrated the peak is
        total = len(timestamps)
        peak_pct = hour_counts[peak_hour] / total
        confidence = round(min(peak_pct * 3, 1.0), 2)

        return {
            'estimated_offset':  estimated_offset,
            'closest_timezone':  closest_tz[0],
            'confidence':        confidence,
            'peak_utc_hour':     peak_hour,
            'assumed_local_peak': assumed_local_peak,
            'note':              f"Estimated based on peak activity at {peak_hour:02d}:00 UTC",
        }

    # ── KMeans Activity Clustering ─────────────────────────────────────────────

    def _cluster_activity(self, timestamps: list) -> list:
        """
        KMeans se activity clusters banao.
        Features: hour of day + day of week
        Clusters = distinct activity sessions
        """
        if len(timestamps) < 6:
            return []

        try:
            # Feature matrix: [hour, day_of_week, normalized_hour_sin, normalized_hour_cos]
            # Circular encoding for hour (0 and 23 are close)
            features = []
            for dt in timestamps:
                hour = dt.hour
                dow  = dt.weekday()
                hour_sin = np.sin(2 * np.pi * hour / 24)
                hour_cos = np.cos(2 * np.pi * hour / 24)
                features.append([hour, dow, hour_sin, hour_cos])

            X = np.array(features)
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            # Optimal k (2-4 clusters)
            best_k       = 2
            best_inertia = None
            for k in range(2, min(5, len(timestamps) // 3 + 1)):
                km = KMeans(n_clusters=k, random_state=42, n_init=10)
                km.fit(X_scaled)
                if best_inertia is None:
                    best_inertia = km.inertia_
                    best_k = k
                elif km.inertia_ < best_inertia * 0.7:  # 30% improvement threshold
                    best_inertia = km.inertia_
                    best_k = k

            km = KMeans(n_clusters=best_k, random_state=42, n_init=10)
            labels = km.fit_predict(X_scaled)

            # Cluster summaries
            clusters = []
            day_names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
            for cluster_id in range(best_k):
                cluster_mask = labels == cluster_id
                cluster_dts  = [timestamps[i] for i in range(len(timestamps)) if cluster_mask[i]]

                if not cluster_dts:
                    continue

                hours = [dt.hour for dt in cluster_dts]
                days  = [dt.weekday() for dt in cluster_dts]

                clusters.append({
                    'cluster_id':  cluster_id,
                    'size':        len(cluster_dts),
                    'peak_hour':   Counter(hours).most_common(1)[0][0],
                    'peak_day':    day_names[Counter(days).most_common(1)[0][0]],
                    'hour_range':  f"{min(hours):02d}:00 - {max(hours):02d}:00",
                    'label':       self._hour_label(Counter(hours).most_common(1)[0][0]),
                })

            return clusters

        except Exception as e:
            logger.debug(f"KMeans clustering failed: {e}")
            return []

    # ── Behavioral Patterns ────────────────────────────────────────────────────

    def _detect_behavioral_patterns(self, timestamps: list) -> list:
        """Unusual behavioral patterns detect karo"""
        patterns = []

        if len(timestamps) < 3:
            return patterns

        hour_counts = Counter(dt.hour for dt in timestamps)
        total = len(timestamps)

        # Late night posting (11pm - 4am)
        late_night = sum(hour_counts.get(h, 0) for h in [23, 0, 1, 2, 3]) / total
        if late_night > 0.3:
            patterns.append({
                'pattern':     'late_night_activity',
                'description': f'{late_night:.0%} of posts between 11pm-4am',
                'severity':    'MEDIUM',
                'osint_value': 'Suggests night shift work, different timezone, or nocturnal habits',
            })

        # Burst posting
        if len(timestamps) >= 2:
            gaps = [(timestamps[i] - timestamps[i-1]).total_seconds() / 60
                    for i in range(1, len(timestamps))]
            very_fast = sum(1 for g in gaps if g < 2)  # Less than 2 minutes
            if very_fast > len(gaps) * 0.2:
                patterns.append({
                    'pattern':     'burst_posting',
                    'description': f'{very_fast} posts within 2 minutes of each other',
                    'severity':    'LOW',
                    'osint_value': 'May indicate bot behavior, copy-paste activity, or emotional state',
                })

        # Consistent schedule (very regular posting)
        if len(timestamps) >= 10:
            gaps = [(timestamps[i] - timestamps[i-1]).total_seconds() / 3600
                    for i in range(1, len(timestamps))]
            gap_std = np.std(gaps)
            gap_mean = np.mean(gaps)
            cv = gap_std / gap_mean if gap_mean > 0 else 0  # Coefficient of variation
            if cv < 0.3:
                patterns.append({
                    'pattern':     'highly_regular_schedule',
                    'description': f'Very consistent posting interval (~{gap_mean:.1f}h)',
                    'severity':    'LOW',
                    'osint_value': 'Scheduled posts or very routine behavior — may be automated',
                })

        # Weekend warrior
        weekend_posts = sum(1 for dt in timestamps if dt.weekday() >= 5)
        if weekend_posts / total > 0.5:
            patterns.append({
                'pattern':     'weekend_dominant',
                'description': f'{weekend_posts/total:.0%} posts on weekends',
                'severity':    'INFO',
                'osint_value': 'Likely has weekday job/school — free time on weekends',
            })

        return patterns

    # ── Content-Time Correlation ───────────────────────────────────────────────

    def _content_time_correlation(self, timestamps: list, texts: list) -> dict:
        """
        Kaunse time pe kaunsa content post karta hai?
        e.g., work-related posts during day, personal at night
        """
        if not texts or len(texts) != len(timestamps):
            return {}

        work_keywords    = ['work', 'office', 'meeting', 'project', 'client', 'deadline', 'boss']
        personal_keywords = ['family', 'home', 'dinner', 'sleep', 'tired', 'weekend', 'vacation']
        rant_keywords    = ['hate', 'angry', 'frustrated', 'annoyed', 'wtf', 'seriously', 'ugh']

        time_content = defaultdict(lambda: {'work': 0, 'personal': 0, 'rant': 0, 'total': 0})

        for dt, text in zip(timestamps, texts):
            if not text:
                continue
            text_lower = text.lower()
            period = self._hour_label(dt.hour)
            time_content[period]['total'] += 1

            if any(kw in text_lower for kw in work_keywords):
                time_content[period]['work'] += 1
            if any(kw in text_lower for kw in personal_keywords):
                time_content[period]['personal'] += 1
            if any(kw in text_lower for kw in rant_keywords):
                time_content[period]['rant'] += 1

        return {
            period: {
                'work_pct':     round(data['work'] / data['total'] * 100, 1) if data['total'] else 0,
                'personal_pct': round(data['personal'] / data['total'] * 100, 1) if data['total'] else 0,
                'rant_pct':     round(data['rant'] / data['total'] * 100, 1) if data['total'] else 0,
                'total_posts':  data['total'],
            }
            for period, data in time_content.items()
            if data['total'] > 0
        }

    # ── OSINT Insights ─────────────────────────────────────────────────────────

    def _generate_insights(self, result: dict) -> list:
        insights = []

        active = result['active_hours']
        freq   = result['posting_frequency']
        tz     = result['timezone_estimate']
        days   = result['active_days']

        # Timezone insight
        if tz.get('closest_timezone') and tz.get('confidence', 0) > 0.3:
            insights.append({
                'type':    'timezone',
                'insight': f"Likely in {tz['closest_timezone']} timezone (offset: UTC{tz['estimated_offset']:+.1f})",
                'confidence': tz['confidence'],
            })

        # Work schedule insight
        if days.get('weekday_pct', 0) > 70:
            insights.append({
                'type':    'schedule',
                'insight': 'Primarily active on weekdays — likely has regular employment/school',
                'confidence': 0.65,
            })

        # Activity time insight
        primary = active.get('primary_activity', '')
        if primary == 'late_night':
            insights.append({
                'type':    'behavior',
                'insight': 'Late night activity pattern — night owl or different timezone',
                'confidence': 0.7,
            })
        elif primary == 'morning':
            insights.append({
                'type':    'behavior',
                'insight': 'Morning activity pattern — early riser, possibly professional',
                'confidence': 0.6,
            })

        # Frequency insight
        pattern = freq.get('pattern', '')
        if pattern == 'very_high_activity':
            insights.append({
                'type':    'behavior',
                'insight': 'Very high posting frequency — heavy social media user or bot',
                'confidence': 0.75,
            })

        # Sleep window
        sleep = active.get('sleep_window', {})
        if sleep:
            insights.append({
                'type':    'schedule',
                'insight': f"Estimated sleep window: {sleep.get('label', 'N/A')} (UTC)",
                'confidence': 0.5,
            })

        return insights

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _date_range(self, timestamps: list) -> dict:
        if not timestamps:
            return {}
        return {
            'first_post': timestamps[0].strftime('%Y-%m-%d %H:%M'),
            'last_post':  timestamps[-1].strftime('%Y-%m-%d %H:%M'),
            'span_days':  (timestamps[-1] - timestamps[0]).days,
        }

    def _empty_result(self) -> dict:
        return {
            'total_posts': 0, 'date_range': {}, 'active_hours': {},
            'active_days': {}, 'posting_frequency': {}, 'timezone_estimate': {},
            'activity_clusters': [], 'behavioral_patterns': [],
            'content_time_corr': {}, 'osint_insights': [],
        }
