#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ghidra Batch SO File Analyzer
===============================
这个 Python 脚本用于批量分析一个目录下的所有 .so 文件
使用 Ghidra Headless 模式 + OHNapiSummary 脚本

功能特性:
- 批量处理多个 .so 文件
- 详细的日志记录
- 失败重试机制
- 进度显示
- 分析报告生成
"""

import os
import sys
import subprocess
import datetime
import argparse
import logging
from pathlib import Path
from typing import List, Dict, Tuple
import json

class GhidraBatchAnalyzer:
    """Ghidra 批量分析器"""
    
    def __init__(self, config: Dict):
        """初始化分析器"""
        self.config = config
        self.results = {
            'total_apps': 0,
            'total_files': 0,
            'success': 0,
            'failed': 0,
            'failed_files': [],
            'app_results': {},
            'start_time': None,
            'end_time': None
        }
        
        # 设置主日志
        self.setup_main_logging()
        
    def setup_main_logging(self):
        """设置主日志系统"""
        log_dir = Path(self.config['log_dir'])
        log_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"batch_analysis_{timestamp}.log"
        
        # 配置主日志格式
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        self.main_log_file = log_file
        
    def setup_app_logging(self, app_name: str):
        """为每个应用设置独立的日志"""
        app_log_dir = Path(self.config['log_dir']) / app_name
        app_log_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        app_log_file = app_log_dir / f"analysis_{timestamp}.log"
        
        # 创建应用专用的logger
        app_logger = logging.getLogger(f"{app_name}_logger")
        app_logger.setLevel(logging.INFO)
        
        # 清除之前的handlers
        app_logger.handlers.clear()
        
        # 添加文件handler
        file_handler = logging.FileHandler(app_log_file, encoding='utf-8')
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        app_logger.addHandler(file_handler)
        
        return app_logger, app_log_file
        
    def validate_environment(self) -> bool:
        """验证运行环境"""
        self.logger.info("正在验证运行环境...")
        
        # 检查 Ghidra headless 脚本
        ghidra_script = self.config['ghidra_headless']
        if not os.path.exists(ghidra_script):
            self.logger.error(f"Ghidra headless 脚本未找到: {ghidra_script}")
            return False
            
        # 检查应用根目录
        apps_root = self.config['apps_root_dir']
        if not os.path.exists(apps_root):
            self.logger.error(f"应用根目录不存在: {apps_root}")
            return False
            
        # 检查脚本路径（可选）
        script_path = self.config.get('script_path')
        if script_path and not os.path.exists(script_path):
            self.logger.warning(f"脚本路径不存在: {script_path}")
            
        self.logger.info("环境验证通过 ✓")
        return True
        
    def find_app_directories(self) -> List[Path]:
        """查找所有应用目录"""
        apps_root = Path(self.config['apps_root_dir'])
        if not apps_root.exists():
            self.logger.error(f"应用根目录不存在: {apps_root}")
            return []
            
        app_dirs = [d for d in apps_root.iterdir() if d.is_dir()]
        self.logger.info(f"在 {apps_root} 中找到 {len(app_dirs)} 个应用目录")
        
        for app_dir in app_dirs:
            self.logger.info(f"  - {app_dir.name}")
            
        return app_dirs
        
    def find_so_files_in_app(self, app_dir: Path) -> List[Path]:
        """查找应用目录中的所有 .so 文件"""
        so_files = list(app_dir.glob("*.so"))
        return so_files
        
    def analyze_single_file(self, so_file: Path, app_logger, index: int, total: int, app_name: str) -> bool:
        """分析单个 .so 文件"""
        file_name = so_file.name
        self.logger.info(f"[{index}/{total}] 正在分析: {app_name}/{file_name}")
        app_logger.info(f"[{index}/{total}] 正在分析: {file_name}")
        
        # 构建命令参数
        cmd_args = [
            self.config['ghidra_headless'],
            str(so_file.parent),
            f"{self.config['project_name']}_{app_name}",
            '-import', str(so_file),
            '-deleteProject'
        ]
         
        # 添加脚本相关参数
        if self.config.get('script_name'):
            cmd_args.extend(['-postScript', self.config['script_name']])
            
        # 添加日志文件 - 每个文件独立日志
        log_file = Path(self.config['log_dir']) / app_name / f"{file_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        cmd_args.extend(['-log', str(log_file)])
        
        try:
            # 运行分析
            process = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=self.config.get('timeout', 600),
                encoding='utf-8',
            )
            
            if process.returncode == 0:
                self.logger.info(f"✓ {app_name}/{file_name} 分析成功")
                app_logger.info(f"✓ {file_name} 分析成功")
                return True
            else:
                self.logger.error(f"✗ {app_name}/{file_name} 分析失败 (返回码: {process.returncode})")
                app_logger.error(f"✗ {file_name} 分析失败 (返回码: {process.returncode})")
                app_logger.error(f"错误输出: {process.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"✗ {app_name}/{file_name} 分析超时")
            app_logger.error(f"✗ {file_name} 分析超时")
            return False
        except Exception as e:
            self.logger.error(f"✗ {app_name}/{file_name} 分析异常: {str(e)}")
            app_logger.error(f"✗ {file_name} 分析异常: {str(e)}")
            return False
            
    def analyze_single_app(self, app_dir: Path) -> Dict:
        """分析单个应用的所有SO文件"""
        app_name = app_dir.name
        self.logger.info(f"开始分析应用: {app_name}")
        
        # 为应用设置独立日志
        app_logger, app_log_file = self.setup_app_logging(app_name)
        
        # 查找SO文件
        so_files = self.find_so_files_in_app(app_dir)
        app_result = {
            'app_name': app_name,
            'total_files': len(so_files),
            'success': 0,
            'failed': 0,
            'failed_files': [],
            'log_file': str(app_log_file),
            'start_time': datetime.datetime.now().isoformat()
        }
        
        if not so_files:
            self.logger.warning(f"应用 {app_name} 中未找到 .so 文件")
            app_logger.warning("未找到 .so 文件")
            app_result['end_time'] = datetime.datetime.now().isoformat()
            return app_result
            
        self.logger.info(f"应用 {app_name} 中找到 {len(so_files)} 个 .so 文件")
        app_logger.info(f"找到 {len(so_files)} 个 .so 文件:")
        for so_file in so_files:
            app_logger.info(f"  - {so_file.name}")
            
        # 分析每个SO文件
        for i, so_file in enumerate(so_files, 1):
            if self.analyze_single_file(so_file, app_logger, i, len(so_files), app_name):
                app_result['success'] += 1
                self.results['success'] += 1
            else:
                app_result['failed'] += 1
                app_result['failed_files'].append(str(so_file))
                self.results['failed'] += 1
                self.results['failed_files'].append(f"{app_name}/{so_file.name}")
                
        app_result['end_time'] = datetime.datetime.now().isoformat()
        
        # 应用分析完成日志
        success_rate = (app_result['success'] / app_result['total_files']) * 100 if app_result['total_files'] > 0 else 0
        self.logger.info(f"应用 {app_name} 分析完成: {app_result['success']}/{app_result['total_files']} 成功 ({success_rate:.1f}%)")
        app_logger.info(f"分析完成: {app_result['success']}/{app_result['total_files']} 成功 ({success_rate:.1f}%)")
        
        return app_result
        
    def run_batch_analysis(self):
        """运行批量分析"""
        self.logger.info("=" * 50)
        self.logger.info("Ghidra 批量 SO 文件分析器启动 - 多应用模式")
        self.logger.info("=" * 50)
        
        # 显示配置信息
        self.logger.info("配置信息:")
        for key, value in self.config.items():
            if key != 'ghidra_headless':  # 路径太长，简化显示
                self.logger.info(f"  {key}: {value}")
                
        # 验证环境
        if not self.validate_environment():
            return False
            
        # 查找应用目录
        app_dirs = self.find_app_directories()
        if not app_dirs:
            self.logger.warning("未找到应用目录，退出分析")
            return True
            
        # 开始分析
        self.results['total_apps'] = len(app_dirs)
        self.results['start_time'] = datetime.datetime.now()
        
        self.logger.info(f"开始批量分析 {len(app_dirs)} 个应用...")
        
        # 分析每个应用
        for i, app_dir in enumerate(app_dirs, 1):
            self.logger.info(f"[{i}/{len(app_dirs)}] 分析应用: {app_dir.name}")
            
            app_result = self.analyze_single_app(app_dir)
            self.results['app_results'][app_dir.name] = app_result
            self.results['total_files'] += app_result['total_files']
            
        self.results['end_time'] = datetime.datetime.now()
        
        # 生成报告
        self.generate_report()
        return True
        
    def generate_report(self):
        """生成分析报告"""
        self.logger.info("=" * 50)
        self.logger.info("批量分析完成报告")
        self.logger.info("=" * 50)
        
        duration = self.results['end_time'] - self.results['start_time']
        success_rate = (self.results['success'] / self.results['total_files']) * 100 if self.results['total_files'] > 0 else 0
        
        report = {
            'summary': {
                'total_apps': self.results['total_apps'],
                'total_files': self.results['total_files'],
                'successful': self.results['success'],
                'failed': self.results['failed'],
                'success_rate': f"{success_rate:.1f}%",
                'duration': str(duration),
                'start_time': self.results['start_time'].isoformat(),
                'end_time': self.results['end_time'].isoformat()
            },
            'app_results': self.results['app_results'],
            'failed_files': self.results['failed_files'],
            'config': self.config
        }
        
        # 输出到控制台
        self.logger.info(f"总应用数: {self.results['total_apps']}")
        self.logger.info(f"总文件数: {self.results['total_files']}")
        self.logger.info(f"成功分析: {self.results['success']}")
        self.logger.info(f"失败分析: {self.results['failed']}")
        self.logger.info(f"成功率: {success_rate:.1f}%")
        self.logger.info(f"分析用时: {duration}")
        self.logger.info(f"主日志文件: {self.main_log_file}")
        
        # 显示每个应用的结果
        self.logger.info("\n各应用分析结果:")
        for app_name, app_result in self.results['app_results'].items():
            app_success_rate = (app_result['success'] / app_result['total_files']) * 100 if app_result['total_files'] > 0 else 0
            self.logger.info(f"  {app_name}: {app_result['success']}/{app_result['total_files']} ({app_success_rate:.1f}%)")
        
        if self.results['failed_files']:
            self.logger.warning("失败的文件:")
            for failed_file in self.results['failed_files']:
                self.logger.warning(f"  - {failed_file}")
                
        # 保存 JSON 报告
        report_file = Path(self.config['log_dir']) / f"analysis_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
            
        self.logger.info(f"详细报告已保存到: {report_file}")


def create_default_config():
    """创建默认配置"""
    # 检测 Ghidra 安装路径
    current_dir = Path(__file__).parent
    if (current_dir / "analyzeHeadless.bat").exists():
        ghidra_headless = str(current_dir / "analyzeHeadless.bat")
    elif (current_dir / "analyzeHeadless").exists():
        ghidra_headless = str(current_dir / "analyzeHeadless")
    else:
        ghidra_headless = "analyzeHeadless.bat"  # 假设在 PATH 中
        
    return {
        'ghidra_headless': ghidra_headless,
        'apps_root_dir': r'D:\WorkSpace\ArkTS_Native\ThirdPartyApps\top6-libs-9.10',
        'project_name': 'batch_analysis',
        'script_name': 'OHNapiSummary',
        'script_path': r'D:\WorkSpace\ArkTS_Native\scripts',
        'log_dir': './analysis_logs',
        'max_memory': '2G',
        'timeout': 600,  # 10分钟，失败或超时就跳过，不重试
        'enable_retry': False  # 禁用重试
    }


def load_config_file(config_path: str = None) -> Dict:
    """加载配置文件"""
    if config_path is None:
        # 默认使用脚本同目录下的 config.json
        config_path = Path(__file__).parent / "config.json"
    
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"警告: 无法加载配置文件 {config_path}: {e}")
            return create_default_config()
    else:
        return create_default_config()


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='Ghidra 批量 SO 文件分析器 - 多应用模式')
    parser.add_argument('--apps-root', help='应用根目录路径')
    parser.add_argument('--script-path', help='Ghidra 脚本路径')
    parser.add_argument('--script-name', help='要执行的脚本名称')
    parser.add_argument('--project-name', help='Ghidra 项目名称')
    parser.add_argument('--log-dir', help='日志输出目录')
    parser.add_argument('--timeout', type=int, help='单个文件分析超时时间(秒)')
    parser.add_argument('--config', help='配置文件路径 (JSON 格式)')
    
    args = parser.parse_args()
    
    # 加载配置
    if args.config and os.path.exists(args.config):
        config = load_config_file(args.config)
    else:
        # 默认尝试加载同目录下的 config.json
        config = load_config_file()
        
    # 命令行参数覆盖配置
    if args.apps_root:
        config['apps_root_dir'] = args.apps_root
    if args.script_path:
        config['script_path'] = args.script_path
    if args.script_name:
        config['script_name'] = args.script_name
    if args.project_name:
        config['project_name'] = args.project_name
    if args.log_dir:
        config['log_dir'] = args.log_dir
    if args.timeout:
        config['timeout'] = args.timeout
        
    # 创建并运行分析器
    analyzer = GhidraBatchAnalyzer(config)
    
    try:
        success = analyzer.run_batch_analysis()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        analyzer.logger.info("用户中断操作")
        sys.exit(130)
    except Exception as e:
        analyzer.logger.error(f"分析过程中发生异常: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
