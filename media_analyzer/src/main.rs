// ============================================================================
// Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
// Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
//
// Unauthorized copying, distribution, or modification of this software,
// via any medium, is strictly prohibited without written permission.
// ============================================================================

use std::env;
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};
use image::{ImageBuffer, Rgb, DynamicImage};
use rayon::prelude::*;
use sha2::{Sha256, Digest};

#[derive(Serialize, Deserialize, Debug)]
struct MediaAnalysis {
    file_path: String,
    file_hash: String,
    analysis_results: AnalysisResults,
    manipulation_indicators: ManipulationIndicators,
    authenticity_score: f64,
    processing_time: f64,
}

#[derive(Serialize, Deserialize, Debug)]
struct AnalysisResults {
    image_dimensions: (u32, u32),
    color_analysis: ColorAnalysis,
    compression_analysis: CompressionAnalysis,
    pixel_analysis: PixelAnalysis,
    geometric_analysis: GeometricAnalysis,
}

#[derive(Serialize, Deserialize, Debug)]
struct ColorAnalysis {
    color_variance: f64,
    histogram_anomalies: f64,
    color_distribution: Vec<f64>,
    unnatural_colors: f64,
}

#[derive(Serialize, Deserialize, Debug)]
struct CompressionAnalysis {
    compression_artifacts: f64,
    quality_estimation: f64,
    block_artifacts: f64,
    recompression_indicators: f64,
}

#[derive(Serialize, Deserialize, Debug)]
struct PixelAnalysis {
    noise_patterns: f64,
    edge_consistency: f64,
    texture_anomalies: f64,
    interpolation_artifacts: f64,
}

#[derive(Serialize, Deserialize, Debug)]
struct GeometricAnalysis {
    perspective_inconsistencies: f64,
    lighting_direction: f64,
    shadow_consistency: f64,
    scale_anomalies: f64,
}

#[derive(Serialize, Deserialize, Debug)]
struct ManipulationIndicators {
    deepfake_probability: f64,
    face_swap_indicators: f64,
    background_manipulation: f64,
    object_insertion: f64,
    color_grading_manipulation: f64,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: media_analyzer <image_path>");
        std::process::exit(1);
    }
    
    let image_path = &args[1];
    
    match analyze_image(image_path) {
        Ok(analysis) => {
            let json_output = serde_json::to_string_pretty(&analysis).unwrap();
            println!("{}", json_output);
        }
        Err(e) => {
            eprintln!("Error analyzing image: {}", e);
            std::process::exit(1);
        }
    }
}

fn analyze_image(image_path: &str) -> Result<MediaAnalysis, Box<dyn std::error::Error>> {
    let start_time = std::time::Instant::now();
    
    // Load image
    let img = image::open(image_path)?;
    let rgb_img = img.to_rgb8();
    
    // Calculate file hash
    let file_data = fs::read(image_path)?;
    let file_hash = calculate_hash(&file_data);
    
    // Perform various analyses
    let color_analysis = analyze_colors(&rgb_img);
    let compression_analysis = analyze_compression(&rgb_img);
    let pixel_analysis = analyze_pixels(&rgb_img);
    let geometric_analysis = analyze_geometry(&rgb_img);
    
    let analysis_results = AnalysisResults {
        image_dimensions: rgb_img.dimensions(),
        color_analysis,
        compression_analysis,
        pixel_analysis,
        geometric_analysis,
    };
    
    // Calculate manipulation indicators
    let manipulation_indicators = calculate_manipulation_indicators(&analysis_results);
    
    // Calculate overall authenticity score
    let authenticity_score = calculate_authenticity_score(&manipulation_indicators);
    
    let processing_time = start_time.elapsed().as_secs_f64();
    
    Ok(MediaAnalysis {
        file_path: image_path.to_string(),
        file_hash,
        analysis_results,
        manipulation_indicators,
        authenticity_score,
        processing_time,
    })
}

fn calculate_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn analyze_colors(img: &ImageBuffer<Rgb<u8>, Vec<u8>>) -> ColorAnalysis {
    let pixels: Vec<&Rgb<u8>> = img.pixels().collect();
    
    // Calculate color variance
    let mut r_values: Vec<f64> = Vec::new();
    let mut g_values: Vec<f64> = Vec::new();
    let mut b_values: Vec<f64> = Vec::new();
    
    for pixel in &pixels {
        r_values.push(pixel[0] as f64);
        g_values.push(pixel[1] as f64);
        b_values.push(pixel[2] as f64);
    }
    
    let r_variance = calculate_variance(&r_values);
    let g_variance = calculate_variance(&g_values);
    let b_variance = calculate_variance(&b_values);
    let color_variance = (r_variance + g_variance + b_variance) / 3.0;
    
    // Simple histogram analysis
    let mut histogram = vec![0; 256];
    for pixel in &pixels {
        let gray = (pixel[0] as u32 + pixel[1] as u32 + pixel[2] as u32) / 3;
        histogram[gray as usize] += 1;
    }
    
    // Detect histogram anomalies (spikes or gaps)
    let histogram_variance = calculate_variance(&histogram.iter().map(|&x| x as f64).collect::<Vec<f64>>());
    let histogram_anomalies = (histogram_variance / 1000000.0).min(1.0);
    
    // Color distribution analysis
    let color_distribution = vec![
        r_values.iter().sum::<f64>() / r_values.len() as f64 / 255.0,
        g_values.iter().sum::<f64>() / g_values.len() as f64 / 255.0,
        b_values.iter().sum::<f64>() / b_values.len() as f64 / 255.0,
    ];
    
    // Detect unnatural colors (simplified)
    let unnatural_colors = detect_unnatural_colors(&pixels);
    
    ColorAnalysis {
        color_variance: color_variance / 10000.0,
        histogram_anomalies,
        color_distribution,
        unnatural_colors,
    }
}

fn analyze_compression(img: &ImageBuffer<Rgb<u8>, Vec<u8>>) -> CompressionAnalysis {
    let (width, height) = img.dimensions();
    
    // Analyze 8x8 blocks for JPEG artifacts
    let mut block_artifacts = 0.0;
    let mut block_count = 0;
    
    for y in (0..height).step_by(8) {
        for x in (0..width).step_by(8) {
            if x + 8 <= width && y + 8 <= height {
                let block_variance = calculate_block_variance(img, x, y, 8, 8);
                block_artifacts += block_variance;
                block_count += 1;
            }
        }
    }
    
    if block_count > 0 {
        block_artifacts /= block_count as f64;
    }
    
    // Estimate compression quality
    let quality_estimation = estimate_jpeg_quality(img);
    
    // Detect recompression indicators
    let recompression_indicators = detect_recompression(img);
    
    CompressionAnalysis {
        compression_artifacts: (block_artifacts / 1000.0).min(1.0),
        quality_estimation,
        block_artifacts: (block_artifacts / 500.0).min(1.0),
        recompression_indicators,
    }
}

fn analyze_pixels(img: &ImageBuffer<Rgb<u8>, Vec<u8>>) -> PixelAnalysis {
    let (width, height) = img.dimensions();
    
    // Noise pattern analysis
    let noise_patterns = calculate_noise_patterns(img);
    
    // Edge consistency analysis
    let edge_consistency = analyze_edge_consistency(img);
    
    // Texture anomaly detection
    let texture_anomalies = detect_texture_anomalies(img);
    
    // Interpolation artifact detection
    let interpolation_artifacts = detect_interpolation_artifacts(img);
    
    PixelAnalysis {
        noise_patterns,
        edge_consistency,
        texture_anomalies,
        interpolation_artifacts,
    }
}

fn analyze_geometry(img: &ImageBuffer<Rgb<u8>, Vec<u8>>) -> GeometricAnalysis {
    // Simplified geometric analysis
    let perspective_inconsistencies = detect_perspective_issues(img);
    let lighting_direction = analyze_lighting_direction(img);
    let shadow_consistency = analyze_shadow_consistency(img);
    let scale_anomalies = detect_scale_anomalies(img);
    
    GeometricAnalysis {
        perspective_inconsistencies,
        lighting_direction,
        shadow_consistency,
        scale_anomalies,
    }
}

fn calculate_manipulation_indicators(analysis: &AnalysisResults) -> ManipulationIndicators {
    // Calculate deepfake probability based on various factors
    let deepfake_probability = (
        analysis.color_analysis.unnatural_colors * 0.3 +
        analysis.pixel_analysis.texture_anomalies * 0.3 +
        analysis.geometric_analysis.lighting_direction * 0.2 +
        analysis.compression_analysis.recompression_indicators * 0.2
    ).min(1.0);
    
    // Face swap indicators
    let face_swap_indicators = (
        analysis.pixel_analysis.edge_consistency * 0.4 +
        analysis.color_analysis.color_variance * 0.3 +
        analysis.geometric_analysis.perspective_inconsistencies * 0.3
    ).min(1.0);
    
    // Background manipulation
    let background_manipulation = (
        analysis.compression_analysis.block_artifacts * 0.4 +
        analysis.pixel_analysis.interpolation_artifacts * 0.3 +
        analysis.color_analysis.histogram_anomalies * 0.3
    ).min(1.0);
    
    // Object insertion
    let object_insertion = (
        analysis.geometric_analysis.scale_anomalies * 0.4 +
        analysis.geometric_analysis.shadow_consistency * 0.3 +
        analysis.pixel_analysis.noise_patterns * 0.3
    ).min(1.0);
    
    // Color grading manipulation
    let color_grading_manipulation = (
        analysis.color_analysis.color_variance * 0.5 +
        analysis.color_analysis.histogram_anomalies * 0.5
    ).min(1.0);
    
    ManipulationIndicators {
        deepfake_probability,
        face_swap_indicators,
        background_manipulation,
        object_insertion,
        color_grading_manipulation,
    }
}

fn calculate_authenticity_score(indicators: &ManipulationIndicators) -> f64 {
    let manipulation_score = (
        indicators.deepfake_probability * 0.3 +
        indicators.face_swap_indicators * 0.25 +
        indicators.background_manipulation * 0.2 +
        indicators.object_insertion * 0.15 +
        indicators.color_grading_manipulation * 0.1
    );
    
    (1.0 - manipulation_score).max(0.0)
}

// Helper functions (simplified implementations)

fn calculate_variance(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance = values.iter()
        .map(|x| (x - mean).powi(2))
        .sum::<f64>() / values.len() as f64;
    
    variance
}

fn detect_unnatural_colors(pixels: &[&Rgb<u8>]) -> f64 {
    let mut unnatural_count = 0;
    
    for pixel in pixels {
        let r = pixel[0] as f64;
        let g = pixel[1] as f64;
        let b = pixel[2] as f64;
        
        // Simple check for oversaturated or unnatural color combinations
        if (r > 240.0 && g < 50.0 && b < 50.0) ||  // Pure red
           (g > 240.0 && r < 50.0 && b < 50.0) ||  // Pure green
           (b > 240.0 && r < 50.0 && g < 50.0) {   // Pure blue
            unnatural_count += 1;
        }
    }
    
    unnatural_count as f64 / pixels.len() as f64
}

fn calculate_block_variance(img: &ImageBuffer<Rgb<u8>, Vec<u8>>, x: u32, y: u32, w: u32, h: u32) -> f64 {
    let mut values = Vec::new();
    
    for dy in 0..h {
        for dx in 0..w {
            if x + dx < img.width() && y + dy < img.height() {
                let pixel = img.get_pixel(x + dx, y + dy);
                let gray = (pixel[0] as u32 + pixel[1] as u32 + pixel[2] as u32) / 3;
                values.push(gray as f64);
            }
        }
    }
    
    calculate_variance(&values)
}

fn estimate_jpeg_quality(img: &ImageBuffer<Rgb<u8>, Vec<u8>>) -> f64 {
    // Simplified JPEG quality estimation based on high-frequency content
    let (width, height) = img.dimensions();
    let mut high_freq_content = 0.0;
    
    for y in 1..height-1 {
        for x in 1..width-1 {
            let center = img.get_pixel(x, y);
            let right = img.get_pixel(x + 1, y);
            let bottom = img.get_pixel(x, y + 1);
            
            let diff_r = (center[0] as i32 - right[0] as i32).abs() + (center[0] as i32 - bottom[0] as i32).abs();
            let diff_g = (center[1] as i32 - right[1] as i32).abs() + (center[1] as i32 - bottom[1] as i32).abs();
            let diff_b = (center[2] as i32 - right[2] as i32).abs() + (center[2] as i32 - bottom[2] as i32).abs();
            
            high_freq_content += (diff_r + diff_g + diff_b) as f64;
        }
    }
    
    // Normalize and convert to quality estimate
    let normalized = high_freq_content / ((width * height) as f64 * 255.0 * 6.0);
    (1.0 - normalized).max(0.0).min(1.0)
}

fn detect_recompression(img: &ImageBuffer<Rgb<u8>, Vec<u8>>) -> f64 {
    // Simplified recompression detection
    let quality = estimate_jpeg_quality(img);
    
    // Lower quality might indicate recompression
    if quality < 0.7 {
        (0.7 - quality) / 0.7
    } else {
        0.0
    }
}

fn calculate_noise_patterns(img: &ImageBuffer<Rgb<u8>, Vec<u8>>) -> f64 {
    // Simplified noise analysis
    let (width, height) = img.dimensions();
    let mut noise_level = 0.0;
    
    for y in 1..height-1 {
        for x in 1..width-1 {
            let center = img.get_pixel(x, y);
            let neighbors = [
                img.get_pixel(x-1, y),
                img.get_pixel(x+1, y),
                img.get_pixel(x, y-1),
                img.get_pixel(x, y+1),
            ];
            
            let mut total_diff = 0.0;
            for neighbor in &neighbors {
                let diff = ((center[0] as i32 - neighbor[0] as i32).abs() +
                           (center[1] as i32 - neighbor[1] as i32).abs() +
                           (center[2] as i32 - neighbor[2] as i32).abs()) as f64;
                total_diff += diff;
            }
            
            noise_level += total_diff / 4.0;
        }
    }
    
    (noise_level / ((width * height) as f64 * 255.0 * 3.0)).min(1.0)
}

fn analyze_edge_consistency(img: &ImageBuffer<Rgb<u8>, Vec<u8>>) -> f64 {
    // Simplified edge consistency analysis
    calculate_noise_patterns(img) // Reuse noise calculation as edge inconsistency indicator
}

fn detect_texture_anomalies(img: &ImageBuffer<Rgb<u8>, Vec<u8>>) -> f64 {
    // Simplified texture analysis
    let (width, height) = img.dimensions();
    let mut texture_variance = 0.0;
    let block_size = 16;
    
    for y in (0..height).step_by(block_size) {
        for x in (0..width).step_by(block_size) {
            let variance = calculate_block_variance(img, x, y, block_size as u32, block_size as u32);
            texture_variance += variance;
        }
    }
    
    (texture_variance / 100000.0).min(1.0)
}

fn detect_interpolation_artifacts(img: &ImageBuffer<Rgb<u8>, Vec<u8>>) -> f64 {
    // Simplified interpolation artifact detection
    calculate_noise_patterns(img) * 0.5 // Use noise patterns as proxy
}

fn detect_perspective_issues(img: &ImageBuffer<Rgb<u8>, Vec<u8>>) -> f64 {
    // Simplified perspective analysis
    0.1 // Placeholder value
}

fn analyze_lighting_direction(img: &ImageBuffer<Rgb<u8>, Vec<u8>>) -> f64 {
    // Simplified lighting analysis
    let (width, height) = img.dimensions();
    let mut brightness_gradient = 0.0;
    
    for y in 0..height {
        for x in 0..width-1 {
            let left = img.get_pixel(x, y);
            let right = img.get_pixel(x + 1, y);
            
            let left_brightness = (left[0] as u32 + left[1] as u32 + left[2] as u32) / 3;
            let right_brightness = (right[0] as u32 + right[1] as u32 + right[2] as u32) / 3;
            
            brightness_gradient += (left_brightness as i32 - right_brightness as i32).abs() as f64;
        }
    }
    
    (brightness_gradient / ((width * height) as f64 * 255.0)).min(1.0)
}

fn analyze_shadow_consistency(img: &ImageBuffer<Rgb<u8>, Vec<u8>>) -> f64 {
    // Simplified shadow analysis
    analyze_lighting_direction(img) * 0.7
}

fn detect_scale_anomalies(img: &ImageBuffer<Rgb<u8>, Vec<u8>>) -> f64 {
    // Simplified scale analysis
    0.05 // Placeholder value
}